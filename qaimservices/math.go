package qaimservices

// standard bytes conversion
func Kb64(b int64) int64 {
	kb := b / 1024
	return kb
}

func Mb64(b int64) int64 {
	mb := Kb64(b) / 1024
	return mb
}

func Gb64(b int64) int64 {
	gb := Mb64(b) / 1024
	return gb
}
