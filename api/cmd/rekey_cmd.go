package main

import (
	"database/sql"
	"fmt"
	"os"
	"sort"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/rekey"
)

// maybeRunRekey handles the one-shot re-key subcommands (`api --rekey`,
// `api --rekey-check`) and returns true if it handled one so main() can exit
// without starting the servers. These run with the main api stopped, so they
// have exclusive DB access. Progress is printed for the orchestrator (manage.sh
// rotate-key) to relay; a non-zero exit means the DB was left unchanged.
func maybeRunRekey() bool {
	if len(os.Args) < 2 {
		return false
	}
	switch os.Args[1] {
	case "--rekey":
		runRekey()
		return true
	case "--rekey-check":
		runRekeyCheck()
		return true
	}
	return false
}

func openRekeyDB() *sql.DB {
	// Set the process key from ENCRYPTION_SECRET so any incidental crypto during
	// schema init works; the re-key itself uses explicit keys, not this global.
	helper.InitEncryption()
	dataDir := helper.GetEnv("DATA_DIR")
	if _, err := database.Init(dataDir); err != nil {
		fmt.Fprintf(os.Stderr, "rekey: open database: %v\n", err)
		os.Exit(1)
	}
	return database.Get()
}

func printReport(rep rekey.Report) {
	cats := make([]string, 0, len(rep.ByCategory))
	for k := range rep.ByCategory {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	for _, c := range cats {
		fmt.Printf("         %-26s %d\n", c, rep.ByCategory[c])
	}
	fmt.Printf("         %-26s %d\n", "total", rep.Total)
	if rep.Skipped > 0 {
		fmt.Printf("         %-26s %d (ephemeral, skipped)\n", "undecryptable non-critical", rep.Skipped)
	}
}

func runRekey() {
	oldHex := os.Getenv("ENCRYPTION_SECRET")
	newHex := os.Getenv("ENCRYPTION_SECRET_NEW")
	if oldHex == "" || newHex == "" {
		fmt.Fprintln(os.Stderr, "rekey: ENCRYPTION_SECRET and ENCRYPTION_SECRET_NEW must both be set")
		os.Exit(1)
	}
	oldKey, _ := helper.ParseKey(oldHex)
	newKey, weak := helper.ParseKey(newHex)
	if weak {
		fmt.Fprintln(os.Stderr, "rekey: refusing to rotate TO a weak key — ENCRYPTION_SECRET_NEW must be 32-byte hex (openssl rand -hex 32)")
		os.Exit(1)
	}
	db := openRekeyDB()
	rep, err := rekey.Run(db, oldKey, newKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rekey: FAILED — database unchanged: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("         re-encrypted:")
	printReport(rep)
	fmt.Println("         committed")
}

func runRekeyCheck() {
	keyHex := os.Getenv("ENCRYPTION_SECRET")
	if keyHex == "" {
		fmt.Fprintln(os.Stderr, "rekey-check: ENCRYPTION_SECRET must be set")
		os.Exit(1)
	}
	key, _ := helper.ParseKey(keyHex)
	db := openRekeyDB()
	rep, err := rekey.Check(db, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rekey-check: FAILED — %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("         %d secrets decrypt OK\n", rep.Total)
}
