package packet

import (
	"bufio"
	"bytes"
	"log"
	"net/http"
	"time"
)

// HTTPHeaderItem is HTTP header key-value pair
type HTTPHeaderItem struct {
	Name  string
	Value string
}

// HTTPEvent is HTTP request or response
type HTTPEvent struct {
	Type      string
	Start     time.Time
	End       time.Time
	StreamSeq uint
}

// HTTPRequestEvent is HTTP request
type HTTPRequestEvent struct {
	HTTPEvent
	ClientAddr string
	ServerAddr string
	Method     string
	URI        string
	Version    string
	Headers    []HTTPHeaderItem
	Body       []byte
}

// HTTPResponseEvent is HTTP response
type HTTPResponseEvent struct {
	HTTPEvent
	ClientAddr string
	ServerAddr string
	Version    string
	Code       uint
	Reason     string
	Headers    []HTTPHeaderItem
	Body       []byte
}

// httpStreamPair is Bi-direction HTTP stream pair
type httpStreamPair struct {
	upStream   *httpStream
	downStream *httpStream

	requestSeq uint
	connSeq    uint
	eventChan  chan<- interface{}
}

// newHTTPStreamPair 实例化httpStreamPair.
func newHTTPStreamPair(seq uint, eventChan chan<- interface{}) *httpStreamPair {
	pair := new(httpStreamPair)
	pair.connSeq = seq
	pair.eventChan = eventChan

	return pair
}

// run 循环处理.
func (pair *httpStreamPair) run() {
	defer func() {
		if r := recover(); r != nil {
			if pair.upStream != nil {
				close(pair.upStream.reader.stopCh)
			}
			if pair.downStream != nil {
				close(pair.downStream.reader.stopCh)
			}
		}
	}()

	for {
		pair.handleTransaction()
		pair.requestSeq++
	}
}

// handleTransaction 处理HTTP事务.
func (pair *httpStreamPair) handleTransaction() {
	upStream := pair.upStream
	reqBytes, method, reqHeaders := upStream.GetRequestBytes()
	reqBody := upStream.getBody(method, reqHeaders, true)
	reqBytes = append(reqBytes, reqBody...)

	downStream := pair.downStream
	resBytes, resHeaders := downStream.GetResponseBytes()
	respBody := downStream.getBody(method, resHeaders, false)
	resBytes = append(resBytes, respBody...)

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(reqBytes)))
	if err != nil {
		log.Printf("read request err: %v\n", err)
	}

	// chunked response不可读取, 需替换过滤.
	var emptyByte []byte
	resBytes = bytes.Replace(resBytes, []byte("Transfer-Encoding: chunked\r\n"), emptyByte, -1)
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(resBytes)), req)
	if err != nil {
		log.Printf("read response err: %v\n", err)
	}

	req.RemoteAddr = upStream.key.net.Src().String()
	pair.eventChan <- Event{
		Req:  req,
		Resp: resp,
	}

}
