package technologies

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/bizibabe/wappaGo/lib"
	"github.com/bizibabe/wappaGo/structure"
	"github.com/bizibabe/wappaGo/utils"
	"github.com/imdario/mergo"
)

func CheckRequired(technoName string, technoList map[string]interface{}, tech []structure.Technologie) []structure.Technologie {
	for name, _ := range technoList[technoName].(map[string]interface{}) {
		if name == "requires" {
			requires := technoList[technoName].(map[string]interface{})["requires"]
			// Tentative d'assertion du type directement en string
			if reqString, ok := requires.(string); ok {
				tech = AddTechno(reqString, tech, technoList)
			} else if reqMap, ok := requires.(map[string]interface{}); ok {
				// Le contenu de requires est un map[string]interface{}, on itère sur les clés
				for req := range reqMap {
					tech = AddTechno(req, tech, technoList)
				}
			} else if reqSlice, ok := requires.([]interface{}); ok {
				// Le contenu de requires est un slice d'interface{}, on itère sur les éléments
				for _, item := range reqSlice {
					if itemStr, ok := item.(string); ok {
						tech = AddTechno(itemStr, tech, technoList)
					} else {
						fmt.Println("Unsupported item type in 'requires' slice")
					}
				}
			} else {
				// Si aucun des types attendus n'est rencontré, affiche une erreur
				fmt.Println("Unexpected type for 'requires'")
			}
		}
		if name == "implies" {
			implies := technoList[technoName].(map[string]interface{})["implies"]
			switch v := implies.(type) {
			case string:
				// Si c'est une chaîne, on ajoute directement la technologie
				tech = AddTechno(v, tech, technoList)
			case []interface{}:
				// Si c'est un slice, on itère sur chaque élément
				for _, item := range v {
					if strItem, ok := item.(string); ok {
						tech = AddTechno(strItem, tech, technoList)
					} else {
						fmt.Println("Unexpected item type in 'implies' slice")
					}
				}
			case map[string]interface{}:
				// Si c'est un map, on itère sur chaque clé
				for key := range v {
					tech = AddTechno(key, tech, technoList)
				}
			default:
				fmt.Println("Unexpected type for 'implies'")
			}
		}
	}
	return tech
}
func AddTechno(name string, tech []structure.Technologie, technoList map[string]interface{}) []structure.Technologie {
	technoTemp := structure.Technologie{}
	technoTemp.Name = name
	if _, ok := technoList[name].(map[string]interface{})["cpe"]; ok {
		technoTemp.Cpe = technoList[name].(map[string]interface{})["cpe"].(string)
	}
	tech = append(tech, technoTemp)
	return tech
}

func LoadTechnologiesFiles(folder string) map[string]interface{} {

	// Open our jsonFile
	var resultGlobal map[string]interface{}
	for _, s := range lib.Find(folder, ".json") {

		jsonFile, err := os.Open(s)
		// if we os.Open returns an error then handle it
		if err != nil {
			fmt.Println(err)
		}
		// defer the closing of our jsonFile so that we can parse it later on
		defer jsonFile.Close()

		byteValue, _ := ioutil.ReadAll(jsonFile)

		var result map[string]interface{}

		json.Unmarshal([]byte(byteValue), &result)
		mergo.Merge(&resultGlobal, result)

	}
	return resultGlobal
}

//go:embed technologies_json/*.json
var embeddedFiles embed.FS

func EmbedTechnologies(folder string) {
	// Check if the folder already exists
	if _, err := os.Stat(folder); os.IsNotExist(err) {
		// Create the folder if it does not exist
		if err := os.MkdirAll(folder, os.ModePerm); err != nil {
			msg := fmt.Sprintf("Error creating folder %s: %v", folder, err)
			jsonResponse := utils.GenerateErrorMessage("Embed", msg)
			log.Fatal(jsonResponse)
		}
	}

	// Traverse embedded files and write them to the folder if they do not already exist
	err := fs.WalkDir(embeddedFiles, "technologies_json", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Determine the output file name
		outputFilePath := filepath.Join(folder, filepath.Base(path))

		// Check if the file already exists
		if _, err := os.Stat(outputFilePath); err == nil {
			return nil
		}

		// Read the content of the embedded file
		fileData, err := embeddedFiles.ReadFile(path)
		if err != nil {
			msg := fmt.Sprintf("Error reading file %s: %v", path, err)
			jsonResponse := utils.GenerateErrorMessage("Embed", msg)
			log.Fatal(jsonResponse)
		}

		// Write the content to the output file
		if err := ioutil.WriteFile(outputFilePath, fileData, 0644); err != nil {
			msg := fmt.Sprintf("Error writing file %s: %v", outputFilePath, err)
			jsonResponse := utils.GenerateErrorMessage("Embed", msg)
			log.Fatal(jsonResponse)
		}

		return nil
	})

	if err != nil {
		msg := fmt.Sprintf("Error retrieving embedded files: %v", err)
		jsonResponse := utils.GenerateErrorMessage("Embed", msg)
		log.Fatal(jsonResponse)
	}
}

func DedupTechno(technologies []structure.Technologie) []structure.Technologie {
	var output []structure.Technologie
	add := true
	for _, tech := range technologies {
		add = true
		for i, checkTech := range output {
			if checkTech == tech {
				add = false
			} else {
				if checkTech.Name == tech.Name {
					if tech.Version != "" && checkTech.Version == "" {
						output[i].Version = tech.Version
					}
					add = false
				}
			}
		}
		if add {
			output = append(output, tech)
		}
	}
	return output
}
