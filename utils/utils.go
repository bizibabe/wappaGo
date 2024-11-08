package utils

import (
	"encoding/json"
	"log"
)

func GenerateErrorMessage(errorType string, msg string) string {
	// Créer la structure du message d'erreur
	errorResponse := map[string]string{
		"error":   errorType,
		"message": msg,
	}

	// Convertir le message d'erreur en JSON
	jsonResponse, err := json.Marshal(errorResponse)
	if err != nil {
		log.Fatalf("Error marshalling JSON: %v", err)
	}

	return string(jsonResponse)
}
