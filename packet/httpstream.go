package packet

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

var (
	httpRequestFirstLine *regexp.Regexp
)

func init() {
	httpRequestFirstLine = regexp.MustCompile(`([A-Z]+) (.+) (HTTP/.+)\r\n`)
}

type streamKey struct {
	net, tcp gopacket.Flow
}

func (k streamKey) String() string {
	return fmt.Sprintf("{%v:%v} -> {%v:%v}", k.net.Src(), k.tcp.Src(), k.net.Dst(), k.tcp.Dst())
}

type httpStream struct {
	reader *StreamReader
	bytes  *uint64
	key    streamKey
	bad    *bool
}

func newHTTPStream(key streamKey) httpStream {
	var s httpStream
	s.reader = NewStreamReader()
	s.bytes = new(uint64)
	s.key = key
	s.bad = new(bool)
	return s
}

// Reassembled 由tcpassembly调用.
func (s httpStream) Reassembled(rs []tcpassembly.Reassembly) {
	if *s.bad {
		return
	}

	for _, r := range rs {
		if r.Skip != 0 {
			*s.bad = true
			return
		}

		if len(r.Bytes) == 0 {
			continue
		}

		*s.bytes += uint64(len(r.Bytes))
		ticker := time.Tick(time.Second)

		select {
		case <-s.reader.stopCh:
			*s.bad = true
			return
		case s.reader.src <- NewStreamDataBlock(r.Bytes, r.Seen):
		case <-ticker:
			// Sometimes pcap only captured HTTP response with no request!
			// Let's wait few seconds to avoid dead lock.
			*s.bad = true
			return
		}
	}
}

// ReassemblyComplete 由tcpassembly调用.
func (s httpStream) ReassemblyComplete() {
	close(s.reader.src)
}

// getChunked 获取chunked内容.
func (s *httpStream) getChunked() []byte {
	var body []byte
	for {
		buf, err := s.reader.ReadUntil([]byte("\r\n"))
		if err != nil {
			panic("Cannot read chuncked content, err=" + err.Error())
		}
		l := string(buf)
		l = strings.Trim(l[:len(l)-2], " ")
		blockSize, err := strconv.ParseInt(l, 16, 32)
		if err != nil {
			panic("bad chunked block length: " + l + ", err=" + err.Error())
		}

		buf, err = s.reader.Next(int(blockSize))
		body = append(body, buf...)
		if err != nil {
			panic("Cannot read chuncked content, err=" + err.Error())
		}
		buf, err = s.reader.Next(2)
		if err != nil {
			panic("Cannot read chuncked content, err=" + err.Error())
		}
		CRLF := string(buf)
		if CRLF != "\r\n" {
			panic("Bad chunked block data")
		}

		if blockSize == 0 {
			break
		}
	}
	return body
}

// getFixedLengthContent 获取固定长度内容.
func (s *httpStream) getFixedLengthContent(contentLength int) []byte {
	body, err := s.reader.Next(contentLength)
	if err != nil {
		panic("Cannot read content, err=" + err.Error())
	}
	return body
}

// getContentInfo 获取请求/响应数据长度和编码.
func getContentInfo(hs []HTTPHeaderItem) (contentLength int, contentEncoding string, contentType string, chunked bool) {
	for _, h := range hs {
		lowerName := strings.ToLower(h.Name)
		if lowerName == "content-length" {
			var err error
			contentLength, err = strconv.Atoi(h.Value)
			if err != nil {
				panic("Content-Length error: " + h.Value + ", err=" + err.Error())
			}
		} else if lowerName == "transfer-encoding" && h.Value == "chunked" {
			chunked = true
		} else if lowerName == "content-encoding" {
			contentEncoding = h.Value
		} else if lowerName == "content-type" {
			contentType = h.Value
		}
	}
	return
}

// getBody 获取请求/响应数据.
func (s *httpStream) getBody(method string, headers []HTTPHeaderItem, isRequest bool) (body []byte) {
	contentLength, contentEncoding, _, chunked := getContentInfo(headers)
	if (contentLength == 0 && !chunked) || (!isRequest && method == "HEAD") {
		return
	}

	if chunked {
		body = s.getChunked()
	} else {
		body = s.getFixedLengthContent(contentLength)
	}

	var err error
	// TODO: 支持更多压缩格式的处理
	switch contentEncoding {
	case "gzip":
		body, err = unGzip(body)
	case "deflate":
		body, err = unDeflate(body)
	default:
	}
	if err != nil {
		body = []byte("(decompression failed)")
	}

	return
}

// GetRequestBytes 获取请求数据.
func (s *httpStream) GetRequestBytes() (bytes []byte, method string, headers []HTTPHeaderItem) {
	lineBytes, err := s.reader.ReadUntil([]byte("\r\n"))
	if err != nil {
		panic("Cannot read request line, err=" + err.Error())
	}
	line := string(lineBytes)
	r := httpRequestFirstLine.FindStringSubmatch(line)
	if len(r) != 4 {
		panic("Bad HTTP Request: " + line)
	}
	method = r[1]

	headerByte, _ := s.reader.ReadUntil([]byte("\r\n\r\n"))
	bytes1 := make([]byte, len(lineBytes))
	bytes2 := make([]byte, len(headerByte))
	copy(bytes1, lineBytes)
	copy(bytes2, headerByte)
	bytes = append(bytes1, bytes2...)
	headers = s.ByteToHeader(headerByte)

	return
}

// GetResponseBytes 获取响应数据.
func (s *httpStream) GetResponseBytes() (bytes []byte, headers []HTTPHeaderItem) {
	lineBytes, _ := s.reader.ReadUntil([]byte("\r\n"))
	headerByte, _ := s.reader.ReadUntil([]byte("\r\n\r\n"))
	bytes1 := make([]byte, len(lineBytes))
	bytes2 := make([]byte, len(headerByte))
	copy(bytes1, lineBytes)
	copy(bytes2, headerByte)
	bytes = append(bytes1, bytes2...)
	headers = s.ByteToHeader(headerByte)

	return
}

// ByteToHeader header转换.
func (s *httpStream) ByteToHeader(headerByte []byte) (headers []HTTPHeaderItem) {
	data := string(headerByte[:len(headerByte)-4])
	for i, line := range strings.Split(data, "\r\n") {
		p := strings.Index(line, ":")
		if p == -1 {
			panic(fmt.Sprintf("Bad http header (line %d): %s", i, data))
		}
		var h HTTPHeaderItem
		h.Name = line[:p]
		h.Value = strings.Trim(line[p+1:], " ")
		headers = append(headers, h)
	}

	return
}

// unGzip gzip解压缩.
func unGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// unDeflate deflate解压缩.
func unDeflate(data []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	defer reader.Close()
	return io.ReadAll(reader)
}
