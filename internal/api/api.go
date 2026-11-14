// Package api exposes the local management API.
package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/semaphore"

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
	service    Service
	probeSlots *semaphore.Weighted
}

func New(service Service, cfg config.Config) http.Handler {
	if cfg.ProbeConcurrency <= 0 {
		cfg.ProbeConcurrency = config.DefaultProbeConcurrency
	}
	h := &handler{service: service, probeSlots: semaphore.NewWeighted(int64(cfg.ProbeConcurrency))}
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
