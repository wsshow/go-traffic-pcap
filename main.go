package main

import (
	"context"
	"go-traffic-pcap/middleware"
	"go-traffic-pcap/router"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func InitLogConfig() {
	log.SetPrefix("[go-traffic-pcap] ")
	log.SetFlags(log.Lshortfile | log.Ldate | log.Lmicroseconds)
}

func InitServer(localPort int) *http.Server {
	//gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(middleware.Cors())
	router.Init(r)
	srv := &http.Server{
		Addr:    ":" + strconv.Itoa(localPort),
		Handler: r,
	}
	log.Println("server run:", localPort)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalln("srv.ListenAndServe error:", err)
		}
	}()
	return srv
}

func ServerRun(localPort int) {
	srv := InitServer(localPort)
	log.Println("before capture signal. the number of goroutines: ", runtime.NumGoroutine())
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	<-c
	close(c)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	log.Println("after capture signal. the remain number of goroutines: ", runtime.NumGoroutine())
}

func main() {
	InitLogConfig()
	ServerRun(9666)
}
