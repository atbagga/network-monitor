package main

import (
	"context"
	"errors"
	"flag"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"

	"network-monitor/internal/service"
	"network-monitor/internal/store"
	"network-monitor/web"
)

func main() {
	dataPath := flag.String("data", filepath.Join("data", "monitor.db"), "SQLite database path")
	port := flag.Int("port", 8787, "Local dashboard port")
	flag.Parse()
	if *port < 1 || *port > 65535 {
		log.Fatal("port must be between 1 and 65535")
	}
	if err := os.MkdirAll(filepath.Dir(*dataPath), 0700); err != nil {
		log.Fatal(err)
	}
	database, err := store.Open(*dataPath)
	if err != nil {
		log.Fatal(err)
	}
	defer database.Close()
	assets, err := fs.Sub(web.Assets, "dist")
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	app := service.New(ctx, database)
	server := &http.Server{
		Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)), Handler: app.Handler(assets),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}
	done := make(chan error, 1)
	schedulerDone := make(chan struct{})
	go func() {
		app.RunScheduler()
		close(schedulerDone)
	}()
	go func() { done <- server.Serve(listener) }()
	log.Printf("Network Monitor: http://%s (local access only; Ctrl+C to stop)", server.Addr)
	log.Printf("Inventory: %s. Scans run only when requested or explicitly scheduled.", *dataPath)
	select {
	case <-ctx.Done():
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server: %v", err)
		}
	}
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	<-schedulerDone
	app.Wait()
}
