package handlers

import (
	"encoding/json"
	"net/http"
	"rest-ws/server"
)

type HomeResponse struct {
	Message string `json:"message"`
	Status  bool   `json:"status"`
}

func HomeHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(HomeResponse{
			Message: "Wellcome to my Home",
			Status:  true,
		})
	}
}
