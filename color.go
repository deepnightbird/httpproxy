package main

import (
	"regexp"
)

var (
	CL_ESC          = "\033"
	CL_BLACK        = CL_ESC + "[0;30m"
	CL_RED          = CL_ESC + "[0;31m"
	CL_GREEN        = CL_ESC + "[0;32m"
	CL_BROWN        = CL_ESC + "[0;33m"
	CL_BLUE         = CL_ESC + "[0;34m"
	CL_PURPLE       = CL_ESC + "[0;35m"
	CL_CYAN         = CL_ESC + "[0;36m"
	CL_LIGHT_GRAY   = CL_ESC + "[0;37m"
	CL_DARK_GRAY    = CL_ESC + "[1;30m"
	CL_LIGHT_RED    = CL_ESC + "[1;31m"
	CL_LIGHT_GREEN  = CL_ESC + "[1;32m"
	CL_YELLOW       = CL_ESC + "[1;33m"
	CL_LIGHT_BLUE   = CL_ESC + "[1;34m"
	CL_LIGHT_PURPLE = CL_ESC + "[1;35m"
	CL_LIGHT_CYAN   = CL_ESC + "[1;36m"
	CL_LIGHT_WHITE  = CL_ESC + "[1;37m"
	CL_BOLD         = CL_ESC + "[1m"
	CL_FAINT        = CL_ESC + "[2m"
	CL_ITALIC       = CL_ESC + "[3m"
	CL_UNDERLINE    = CL_ESC + "[4m"
	CL_BLINK        = CL_ESC + "[5m"
	CL_NEGATIVE     = CL_ESC + "[7m"
	CL_CROSSED      = CL_ESC + "[9m"
	CL_RESET        = CL_ESC + "[0m"
)

const ansi = "\\033\\[[0-9;]*m"

var re = regexp.MustCompile(ansi)

func Strip(str string) string {
	return re.ReplaceAllString(str, "")
}