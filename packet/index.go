package packet

import (
	"context"
	"net/http"
	"time"
)

type (
	Event struct {
		Req  *http.Request
		Resp *http.Response
	}
	EventFunc func(req *http.Request, resp *http.Response)
	Handle    struct {
		ctx          context.Context  // 上下文.
		cardName     string           // 网卡名称.
		bpf          string           // 过滤器规则.
		promisc      bool             // 是否混杂模式.
		eventCh      chan interface{} // 事件通道.
		goroutineNum int              // 协程数量.
		eventHandle  EventFunc        // 事件处理.
		flushTime    time.Duration    // 清理缓存时间.
	}
)

func NewPacketHandle(ctx context.Context, cardName string, eventCh chan interface{}) *Handle {
	return &Handle{
		ctx:       ctx,
		cardName:  cardName,
		bpf:       "tcp",
		promisc:   false,
		eventCh:   eventCh,
		flushTime: time.Minute * -2,
	}
}

// SetBpf 设置过滤器规则.
func (slf *Handle) SetBpf(bpf string) *Handle {
	slf.bpf = bpf
	return slf
}

// SetPromisc 设置混杂模式.
func (slf *Handle) SetPromisc(promise bool) *Handle {
	slf.promisc = promise
	return slf
}

// SetEventHandle 设置多协程事件处理.
func (slf *Handle) SetEventHandle(goroutineNum int, handle EventFunc) *Handle {
	slf.goroutineNum = goroutineNum
	slf.eventHandle = handle
	return slf
}

// SetFlushTime 设置清理缓存时间,
// 清除收到的最后一个数据包时间加上此时间之前的所有的数据包.
func (slf *Handle) SetFlushTime(timer time.Duration) *Handle {
	slf.flushTime = timer.Abs() * -1
	return slf
}
