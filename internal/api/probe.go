package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"onesocks/internal/domain"

	"github.com/gin-gonic/gin"
)

func (h *handler) probe(kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		if err := h.probeSlots.Acquire(ctx, 1); err != nil {
			serviceError(c, err)
			return
		}
		defer h.probeSlots.Release(1)
		result, err := h.service.Probe(ctx, c.Param("id"), kind)
		respond(c, http.StatusOK, result, err)
	}
}

type probeResult struct {
	ID    string            `json:"id"`
	Node  *domain.NodeInfo  `json:"node,omitempty"`
	Error map[string]string `json:"error,omitempty"`
}

func (h *handler) probeBatch(c *gin.Context) {
	var input struct {
		IDs  []string `json:"ids"`
		Kind string   `json:"kind"`
	}
	if !decode(c, &input) {
		return
	}
	if input.Kind != "latency" && input.Kind != "ip-check" {
		writeError(c, http.StatusBadRequest, "invalid_input", "kind must be latency or ip-check")
		return
	}

	// Gin's Flush discards underlying errors. Unwrap it so a failed flush also
	// cancels the batch, including when the JSON itself fit in an HTTP buffer.
	writer := http.ResponseWriter(c.Writer)
	if unwrapper, ok := writer.(interface{ Unwrap() http.ResponseWriter }); ok {
		writer = unwrapper.Unwrap()
	}
	controller := http.NewResponseController(writer)
	encoder := json.NewEncoder(c.Writer)
	write := func(result *probeResult) error {
		// Queueing and probing have no total stream deadline. Limit only the
		// time spent writing each response, so slow readers cannot hold slots.
		if err := controller.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return err
		}
		defer controller.SetWriteDeadline(time.Time{})
		c.Writer.WriteHeaderNow()
		if result != nil {
			if err := encoder.Encode(result); err != nil {
				return err
			}
		}
		return controller.Flush()
	}
	c.Header("Content-Type", "application/x-ndjson; charset=utf-8")
	if err := write(nil); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(c.Request.Context())
	results := make(chan probeResult)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.runBatch(ctx, input.IDs, input.Kind, results)
	}()
	defer func() {
		cancel()
		<-done
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-results:
			if !ok || write(&result) != nil {
				return
			}
		}
	}
}

func (h *handler) runBatch(ctx context.Context, ids []string, kind string, results chan<- probeResult) {
	defer close(results)
	var workers sync.WaitGroup
	defer workers.Wait()
	for _, id := range ids {
		// Acquire before starting a goroutine: queued IDs consume no worker or
		// node lease. Scheduling runs separately from the NDJSON response writer.
		if err := h.probeSlots.Acquire(ctx, 1); err != nil {
			return
		}
		workers.Go(func() {
			defer h.probeSlots.Release(1)
			if ctx.Err() != nil {
				return
			}
			node, err := h.service.Probe(ctx, id, kind)
			result := probeResult{ID: id}
			if err == nil {
				result.Node = &node
			} else {
				code := "internal_error"
				var detail *domain.Error
				switch {
				case errors.As(err, &detail):
					code = detail.Code
				case errors.Is(err, context.DeadlineExceeded):
					code = "timeout"
				case errors.Is(err, context.Canceled):
					code = "canceled"
				}
				result.Error = map[string]string{"code": code, "message": err.Error()}
			}
			select {
			case results <- result:
			case <-ctx.Done():
			}
		})
	}
}
