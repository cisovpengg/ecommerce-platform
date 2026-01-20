// E-commerce Platform - Main Server Entry Point
// Human-written server initialization and configuration

package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/demo/ecommerce-platform/pkg/auth"
	"github.com/demo/ecommerce-platform/pkg/cart"
	"github.com/demo/ecommerce-platform/pkg/checkout"
	"github.com/demo/ecommerce-platform/pkg/inventory"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	r := gin.Default()

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// API routes
	api := r.Group("/api")
	{
		// Cart endpoints
		api.GET("/cart", cart.GetCart)
		api.POST("/cart/items", cart.AddItem)
		api.DELETE("/cart/items/:id", cart.RemoveItem)

		// Checkout endpoints
		api.POST("/checkout", checkout.ProcessCheckout)
		api.GET("/orders/:id", checkout.GetOrder)

		// Inventory endpoints
		api.GET("/products", inventory.ListProducts)
		api.GET("/products/:id", inventory.GetProduct)
		api.GET("/products/:id/availability", inventory.CheckAvailability)

		// Auth endpoints (protected zone)
		api.POST("/auth/login", auth.Login)
		api.POST("/auth/refresh", auth.RefreshToken)
		api.GET("/auth/verify", auth.VerifyToken)
	}

	log.Printf("Starting e-commerce server on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
