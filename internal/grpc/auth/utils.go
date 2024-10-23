package authgrpc

import "net/url"

func isValidRedirectUrl(redirectUrl string) bool {
	parsedUrl, err := url.Parse(redirectUrl)
	if err != nil {
		return false
	}
	if parsedUrl.Scheme == "" || parsedUrl.Host == "" {
		return false
	}
	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return false
	}
	return true
}
