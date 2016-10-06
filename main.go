package main

import (
	"fmt"
	"log"
	"time"
	"net/http"
	"reflect"
	"strings"
	_ "net/http/pprof"
	"encoding/json"
	"github.com/jinzhu/gorm"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
	"github.com/rs/cors"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id       int
	Name     string `json:"name" validate:"required"`
	Surname  string `json:"surname" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`

	jwt.StandardClaims
}

var validate *validator.Validate

func main() {
	validate = validator.New()

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]

		if name == "-" {
			return ""
		}

		return name
	})

	commonHandlers := alice.New(loggingHandler, recoverHandler)

	router := httprouter.New()
	router.Handler("POST", "/login", commonHandlers.ThenFunc(login))
	router.Handler("POST", "/register", commonHandlers.ThenFunc(register))

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"OPTIONS", "DELETE", "GET", "PUT", "POST"},
		AllowedHeaders: []string{"*"},
		AllowCredentials: true,
		Debug: true,
	})

	log.Println(http.ListenAndServe(":8080", c.Handler(router)))
}

func loggingHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t1 := time.Now()
		next.ServeHTTP(w, r)
		t2 := time.Now()
		log.Printf("[%s] %q %v\n", r.Method, r.URL.String(), t2.Sub(t1))
	})
}

func recoverHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic %+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	log.Println("Responsing to /login request")

	//expireToken := time.Now().Add(time.Hour * 1).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	signedToken, _ := token.SignedString([]byte("secret"))

	m := make(map[string]string)
	m["token"] = signedToken

	json, _ := json.Marshal(m)

	w.Write(json)

	w.WriteHeader(http.StatusOK)
}

func register(w http.ResponseWriter, r *http.Request) {
	log.Println("Responding to /register request")

	db, _ := gorm.Open("postgres", "host=localhost user=postgres dbname=backend sslmode=disable password=initpass")
	db.LogMode(true)

	userMap := make(map[string]string)
	json.NewDecoder(r.Body).Decode(&userMap)

	password := userMap["password"]
	if len(password) > 0 {
		password = encodePassword(userMap["password"])
	}

	userOne := User{Email: userMap["email"], Name: userMap["name"], Surname: userMap["surname"], Password: password}

	w.Header().Set("Content-Type", "application/json")

	if result, errs := validateStruct(userOne); !result {
		fmt.Println(errs)
		json, _ := json.Marshal(errs)

		w.WriteHeader(http.StatusBadRequest)
		w.Write(json)
		return
	}

	db.Save(&userOne)
	w.WriteHeader(http.StatusOK)

}

func encodePassword(password string) string {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		panic(err)
	}

	return string(hashedPassword)
}

func validateStruct(s interface{}) (bool, map[string]string) {
	err := validate.Struct(s)

	if err == nil {
		return true, nil
	}

	errs := map[string]string{}

	for _, err := range err.(validator.ValidationErrors) {
		errs[err.Field()] = humanValidationMessage(err.Tag())
	}

	return false, errs
}

func humanValidationMessage(tag string) string {
	switch tag {
	case "required":
		return "Field can't be blank"
	case "email":
		return "Not an valid email address"
	case "unique":
		return "Has already been taken"
	default:
		return ""
	}
}