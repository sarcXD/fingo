package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	qroutes "qaimbe/qaimroutes"
	qaimservices "qaimbe/qaimservices"

	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

/*
 ! Important Notes
 TODO: implement better error handling
 TODO: implement logging
*/

func main() {
	envType := os.Getenv("DEPLOY_ENV")
	if envType == qaimservices.EnvProd {
		godotenv.Load("prod.env")
	} else if envType == qaimservices.EnvDev {
		godotenv.Load("dev.env")
	} else if envType == qaimservices.EnvLocal {
		godotenv.Load("local.env")
	} else {
		return
	}
	err := qaimservices.InitAppState(envType)
	if err != nil {
		log.Fatal(err)
	}
	defer qaimservices.GlobalState.ConnPool.Close()
	mux := http.NewServeMux() // ! what is a serve mux
	mux.HandleFunc("/user/", func(w http.ResponseWriter, r *http.Request) {
		qroutes.UserHandler(w, r, qaimservices.GlobalState.ConnPool)
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		qroutes.AdminHandler(w, r, qaimservices.GlobalState.ConnPool)
	})
	mux.HandleFunc("/test/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "This is a test message, indicating that the backend server is live")
	})

	cors := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "https://localhost:3000", "https://qaim-prod.netlify.app"},
		AllowedHeaders:   []string{"Content-Type", "Token"},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodOptions},
		Debug:            true,
		AllowCredentials: true,
	})
	handler := cors.Handler(mux)

	if envType == qaimservices.EnvProd {
		tlsAddress := "0.0.0.0:" + os.Getenv("TLSPORT")
		certPath := os.Getenv("TLSCERTPATH")
		keyPath := os.Getenv("TLSKEYPATH")
		fmt.Printf("Qaim-be running \n-----------------\nServer listening at http(s)://%s\n", tlsAddress)
		log.Fatal(http.ListenAndServeTLS(tlsAddress, certPath, keyPath, handler))
	} else if envType == qaimservices.EnvDev || envType == qaimservices.EnvLocal {
		address := "0.0.0.0:" + os.Getenv("PORT")
		fmt.Printf("Qaim-be running \n-----------------\nServer listening at http://%s\n", address)
		http.ListenAndServe(address, handler)
	}
}
