package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

type LoginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

type SignUpRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	connStr := os.Getenv("DB_CONN_STR")
	db, err := connectDB(connStr)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	c := cors.AllowAll()

	http.HandleFunc("/login", loginHandler(db))
	http.HandleFunc("/signup", signupHandler(db))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s...", port)
	log.Fatal(http.ListenAndServe(":"+port, c.Handler(http.DefaultServeMux)))
}

func connectDB(connStr string) (*sql.DB, error) {
	db, err := sql.Open("mysql", connStr)
	if err != nil {
		return nil, err
	}
	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return db, nil
}

func loginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var loginReq LoginRequest
		err := json.NewDecoder(r.Body).Decode(&loginReq)
		if err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		var storedPassword, username, email string
		err = db.QueryRow("SELECT password, username, email FROM users WHERE username = ? OR email = ?", loginReq.Identifier, loginReq.Identifier).Scan(&storedPassword, &username, &email)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Invalid username/email or password", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(loginReq.Password))
		if err != nil {
			http.Error(w, "Invalid username/email or password", http.StatusUnauthorized)
			return
		}

		response := map[string]string{
			"username": username,
			"email":    email,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func signupHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var signUpReq SignUpRequest
		err := json.NewDecoder(r.Body).Decode(&signUpReq)
		if err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Check if the username or email already exists
		var existingUserCount int
		err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ? OR email = ?", signUpReq.Username, signUpReq.Email).Scan(&existingUserCount)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if existingUserCount > 0 {
			http.Error(w, "Username or email already exists", http.StatusConflict)
			return
		}

		// Hash the password before storing it
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(signUpReq.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", signUpReq.Username, signUpReq.Email, hashedPassword)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		w.Write([]byte("Sign up successful"))
	}
}
