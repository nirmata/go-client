package client

import (
	"log/slog"
	"os"
)

var (
	leveler = new(slog.LevelVar)
	logger  = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: leveler,
	}))
)

func init() {
	LogLevel(slog.LevelWarn)
}

func LogLevel(l slog.Level) {
	leveler.Set(l)
}
