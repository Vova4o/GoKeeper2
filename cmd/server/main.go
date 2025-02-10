package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/vova4o/gokeeper2/internal/server/flags"
	"github.com/vova4o/gokeeper2/internal/server/handlers"
	"github.com/vova4o/gokeeper2/internal/server/service"
	"github.com/vova4o/gokeeper2/internal/server/storage"
	"github.com/vova4o/gokeeper2/package/jwtauth"
	"github.com/vova4o/gokeeper2/package/logger"

	pb "github.com/vova4o/gokeeper2/protobuf/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	if _, err := os.Stat("server.key"); os.IsNotExist(err) {
		err := generateCerts()
		if err != nil {
			log.Fatalf("failed to generate certs: %v", err)
		}
	}

	settings := flags.NewSettings()
	settings.LoadConfig()

	// Start logger
	logger := logger.NewLogger(settings.LogLevel)

	logger.Info("Welcome to the server!")

	port := strconv.Itoa(settings.Port)

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	creds, err := credentials.NewServerTLSFromFile("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load TLS credentials: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stor, err := storage.NewStorage(ctx, settings.DSN, logger)
	if err != nil {
		log.Printf("failed to create storage: %v", err)
		return
	}

	jwtService := jwtauth.NewJWTService(settings.Secret, settings.Issuer)
	serv := service.NewService(stor, settings.Secret, settings.Issuer, logger)

	authService := handlers.NewHandlersService(jwtService, serv, logger)

	s := grpc.NewServer(grpc.Creds(creds), grpc.UnaryInterceptor(authService.AuthFuncOverride))
	pb.RegisterAuthServiceServer(s, authService)

	// Запуск HTTP сервера для передачи сертификатов клиенту
	go func() {
		http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "server.crt")
		})
		log.Println("HTTP server for certificate is running on port 8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down server...")
		s.GracefulStop()
		cancel()
		log.Println("Server shut down gracefully")
	}()

	log.Println("gRPC server is running on port", port)
	if err := s.Serve(lis); err != nil {
		log.Printf("failed to serve: %v", err)
		return
	}
}

func generateCerts() error {
	cmd := exec.Command("/bin/sh", "generate_cert.sh")
	return cmd.Run()
}
