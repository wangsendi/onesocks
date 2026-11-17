package service

import (
	"strconv"
	"strings"
	"time"

	"onesocks/internal/domain"
)

func parseSubscriptionTraffic(headers []string) *domain.SubscriptionTraffic {
	traffic := &domain.SubscriptionTraffic{}
	for _, part := range strings.Split(strings.Join(headers, ";"), ";") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		number, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "upload":
			traffic.UploadBytes = &number
		case "download":
			traffic.DownloadBytes = &number
		case "total":
			traffic.TotalBytes = &number
		case "expire":
			// Zero means no expiry supplied; JSON timestamps cannot exceed year 9999.
			if number > 0 && number <= 253402300799 {
				expires := time.Unix(int64(number), 0).UTC()
				traffic.ExpiresAt = &expires
			}
		}
	}
	if traffic.UploadBytes == nil && traffic.DownloadBytes == nil && traffic.TotalBytes == nil && traffic.ExpiresAt == nil {
		return nil
	}
	return traffic
}
