package providers

import "os"

func getConfigOrDefault(config map[string]string, key, defaultValue string) string {
	if value, exists := config[key]; exists && value != "" {
		return value
	}
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
