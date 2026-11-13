// Package api exposes the local management API.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"onesocks/internal/config"
	"onesocks/internal/domain"
)

type Service interface {
	Nodes(subscriptionID string) domain.NodeList
	Subscriptions() []domain.SubscriptionInfo
	Create(context.Context, domain.SubscriptionInput) (domain.MutationResult, error)
	Update(context.Context, string, domain.SubscriptionPatch) (domain.MutationResult, error)
	Refresh(context.Context, string) (domain.MutationResult, error)
	Delete(context.Context, string) error
	Probe(context.Context, string, string) (domain.NodeInfo, error)
	Status() domain.Status
}

type handler struct {
	service Service
}

func New(service Service, cfg config.Config) http.Handler {
	h := &handler{service: service}
	router := gin.New()
	router.RedirectTrailingSlash = false
	router.HandleMethodNotAllowed = true
	router.Use(requestMiddleware(cfg.APIToken))
	router.NoRoute(func(c *gin.Context) {
		writeError(c, http.StatusNotFound, "not_found", "API endpoint not found")
	})
	router.NoMethod(func(c *gin.Context) {
		writeError(c, http.StatusMethodNotAllowed, "method_not_allowed", "method is not supported for this endpoint")
	})
	router.GET("/api/nodes", func(c *gin.Context) {
		c.JSON(http.StatusOK, service.Nodes(c.Query("subscription_id")))
	})
	router.GET("/api/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, service.Status())
	})
	router.GET("/api/config", func(c *gin.Context) {
		c.JSON(http.StatusOK, cfg)
	})
	router.GET("/api/subscriptions", func(c *gin.Context) {
		items := service.Subscriptions()
		if items == nil {
			items = []domain.SubscriptionInfo{}
		}
		c.JSON(http.StatusOK, struct {
			Items []domain.SubscriptionInfo `json:"items"`
		}{items})
	})
	router.POST("/api/subscriptions", h.create)
	router.POST("/api/subscribe", h.create)
	router.PATCH("/api/subscriptions/:id", h.update)
	router.DELETE("/api/subscriptions/:id", h.delete)
	router.DELETE("/api/subscribe/:id", h.delete)
	router.POST("/api/subscriptions/:id/refresh", h.refresh)
	router.POST("/api/nodes/probe", h.probeBatch)
	router.POST("/api/nodes/:id/latency", h.probe("latency"))
	router.POST("/api/nodes/:id/ip-check", h.probe("ip-check"))
	return router
}

func requestMiddleware(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", "application/json; charset=utf-8")
		c.Header("Cache-Control", "no-store")
		c.Header("X-Content-Type-Options", "nosniff")
		if token != "" && subtle.ConstantTimeCompare([]byte(c.GetHeader("Authorization")), []byte("Bearer "+token)) != 1 {
			c.Header("WWW-Authenticate", "Bearer")
			// Gin sets Allow before middleware when a route rejects the method.
			c.Writer.Header().Del("Allow")
			writeError(c, http.StatusUnauthorized, "unauthorized", "a valid Bearer token is required")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (h *handler) create(c *gin.Context) {
	var input domain.SubscriptionInput
	if !decode(c, &input) {
		return
	}
	result, err := h.service.Create(c.Request.Context(), input)
	if err == nil {
		c.Header("Location", "/api/subscriptions/"+result.Subscription.ID)
	}
	respond(c, http.StatusCreated, result, err)
}

func (h *handler) update(c *gin.Context) {
	var input domain.SubscriptionPatch
	if !decode(c, &input) {
		return
	}
	result, err := h.service.Update(c.Request.Context(), c.Param("id"), input)
	respond(c, http.StatusOK, result, err)
}

func (h *handler) refresh(c *gin.Context) {
	result, err := h.service.Refresh(c.Request.Context(), c.Param("id"))
	respond(c, http.StatusOK, result, err)
}

func (h *handler) probe(kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		result, err := h.service.Probe(c.Request.Context(), c.Param("id"), kind)
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
	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()
	results := make(chan probeResult)
	for _, id := range input.IDs {
		go func() {
			node, err := h.service.Probe(ctx, id, input.Kind)
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
		}()
	}
	c.Header("Content-Type", "application/x-ndjson; charset=utf-8")
	c.Writer.Flush()
	encoder := json.NewEncoder(c.Writer)
	for range input.IDs {
		select {
		case <-ctx.Done():
			return
		case result := <-results:
			if err := encoder.Encode(result); err != nil {
				return
			}
			c.Writer.Flush()
		}
	}
}

func (h *handler) delete(c *gin.Context) {
	if err := h.service.Delete(c.Request.Context(), c.Param("id")); err != nil {
		serviceError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func decode(c *gin.Context, value any) bool {
	if err := c.ShouldBindJSON(value); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_input", err.Error())
		return false
	}
	return true
}

func respond(c *gin.Context, status int, result any, err error) {
	if err != nil {
		serviceError(c, err)
		return
	}
	c.JSON(status, result)
}

func serviceError(c *gin.Context, err error) {
	var e *domain.Error
	if errors.As(err, &e) {
		status := http.StatusInternalServerError
		switch e.Code {
		case "invalid_input":
			status = http.StatusBadRequest
		case "not_found":
			status = http.StatusNotFound
		case "conflict":
			status = http.StatusConflict
		case "fetch_failed":
			status = http.StatusBadGateway
		case "parse_failed":
			status = http.StatusUnprocessableEntity
		case "closed":
			status = http.StatusServiceUnavailable
		case "canceled":
			status = http.StatusRequestTimeout
		}
		writeError(c, status, e.Code, e.Message)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		writeError(c, http.StatusGatewayTimeout, "timeout", "operation timed out")
		return
	}
	if errors.Is(err, context.Canceled) {
		writeError(c, http.StatusRequestTimeout, "canceled", "operation was canceled")
		return
	}
	writeError(c, http.StatusInternalServerError, "internal_error", err.Error())
}

func writeError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}
