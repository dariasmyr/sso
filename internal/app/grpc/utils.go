package grpcapp

func maskSensitiveFields(fields []any) []any {
	for i := 0; i < len(fields)-1; i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue
		}
		if key == "password" || key == "pwd" || key == "pass" {
			if pwd, ok := fields[i+1].(string); ok {
				if len(pwd) > 4 {
					fields[i+1] = pwd[:1] + "****" + pwd[len(pwd)-1:]
				} else {
					fields[i+1] = "****"
				}
			}
		}
	}
	return fields
}
