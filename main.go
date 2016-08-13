package main

import (
	"fmt"
	"log"
	"net/http"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type User struct {
	Name     string
	Surname  string
	Email    string
	Password string
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/register", register).Methods("POST")

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"OPTIONS", "DELETE", "GET", "PUT", "POST"},
		AllowCredentials: true,
	})

	handler := cors.Default().Handler(router)
	handler = c.Handler(handler)

	http.ListenAndServe(":8080", handler)
}

func login(w http.ResponseWriter, r *http.Request) {
	log.Println("Responsing to /hello request")
	log.Println(r.UserAgent())

	vars := mux.Vars(r)
	name := vars["name"]

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Hello:", name)
}

func register(w http.ResponseWriter, r *http.Request) {
	log.Println("Responsing to /register request")
	vars := mux.Vars(r)

	fmt.Fprintln(w, "Hello:", vars["name"])
	fmt.Fprintln(w, "Hello:", vars["surname"])
	fmt.Fprintln(w, "Hello:", vars["email"])
	fmt.Fprintln(w, "Hello:", vars["password"])

	w.WriteHeader(http.StatusOK)
}