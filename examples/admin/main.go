// Example admin compiles a control-plane contract into a runtime admin shell.
package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/MiraiMagicLab/go-platform-kit/admin"
)

func main() {
	raw := []byte(`{
		"admin": {
			"schemaVersion": "v3",
			"sections": ["overview", {"id": "users", "title": "Users"}]
		}
	}`)
	if path := os.Getenv("CONTRACT_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		raw = b
	}

	shell, err := admin.Compile(raw)
	if err != nil {
		log.Fatal(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(shell); err != nil {
		log.Fatal(err)
	}
}
