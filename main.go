package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	openai "github.com/sashabaranov/go-openai"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var ignoreFiles = map[string]bool{
	"pyi_rth_inspect.txt":              true,
	"pyi_rth_multiprocessing.txt":      true,
	"pyi_rth_pkgres.txt":               true,
	"pyi_rth_pkgutil.txt":              true,
	"pyi_rth_setuptools.txt":           true,
	"pyiboot01_bootstrap.txt":          true,
	"pyi_rth_cryptography_openssl.txt": true,
	"pyi_rth_certifi.txt":              true,
}

type MalwareAnalyzer struct {
	client       *openai.Client
	systemPrompt string
}

func NewMalwareAnalyzer(apiKey string) *MalwareAnalyzer {
	return &MalwareAnalyzer{
		client: openai.NewClient(apiKey),
		systemPrompt: "Check if the provided code is considered a virus or malware. " +
			"If it is, return `True`; otherwise, return `False`. " +
			"Don't describe anything. Return a boolean value: `True` or `False`.",
	}
}

func (m *MalwareAnalyzer) extractStringData(filePath string) ([]string, error) {
	cmd := exec.Command("strings", filePath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to extract strings: %v", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, nil
}

func (m *MalwareAnalyzer) decompilePython(filePath string) ([]string, error) {
	cmd := exec.Command("./files/pyinstxtractor", filePath)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run pyinstxtractor: %v", err)
	}

	extractedPath := strings.Replace(filePath+"_extracted", "files/", "", 1)
	cmd = exec.Command("sh", "-c", fmt.Sprintf("ls %s | grep .txt", extractedPath))
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %v", err)
	}

	var filenames []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		fname := scanner.Text()
		if !ignoreFiles[fname] {
			name := strings.TrimSuffix(fname, ".txt")
			filenames = append(filenames, name)
		}
	}

	for _, filename := range filenames {
		outputName := strings.ReplaceAll(filename, " ", "_")
		cmd = exec.Command("sh", "-c",
			fmt.Sprintf("pydec \"%s/%s.pyc\" >> ./%s.py",
				extractedPath, filename, outputName))
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to decompile %s: %v", filename, err)
		}
		fmt.Printf("Decompiled %s\n", outputName)
	}

	return filenames, nil
}

func (m *MalwareAnalyzer) clearString(s string) string {
	re := regexp.MustCompile("[^a-zA-Z0-9./]")
	cleanedString := re.ReplaceAllString(s, " ")
	words := strings.Fields(cleanedString)
	var result []string
	for _, word := range words {
		if len(word) >= 7 {
			result = append(result, word)
		}
	}
	return strings.ReplaceAll(strings.Join(result, " "), "'',", "")
}

func (m *MalwareAnalyzer) analyzeCode(code string) (bool, error) {
	resp, err := m.client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: "gpt-4o-mini",
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    "system",
					Content: m.systemPrompt,
				},
				{
					Role:    "user",
					Content: code,
				},
			},
		},
	)
	if err != nil {
		return false, fmt.Errorf("failed to analyze code: %v", err)
	}

	return strings.ToLower(resp.Choices[0].Message.Content) == "true", nil
}

func cleanup(filePath string, decompiledFiles []string) {
	filePath = strings.Replace(filePath, "files/", "", 1)
	os.RemoveAll(filePath + "_extracted")
	for _, filename := range decompiledFiles {
		outputName := strings.ReplaceAll(filename, " ", "_")
		os.Remove(outputName + ".py")
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please provide a file path")
		os.Exit(1)
	}

	analyzer := NewMalwareAnalyzer("OPENAI_API_KEY")
	filePath := "files/"+os.Args[1]

	stringData, err := analyzer.extractStringData(filePath)
	if err != nil {
		fmt.Printf("Error extracting strings: %v\n", err)
		os.Exit(1)
	}

	combinedStringData := strings.Join(stringData, "\n")
	if strings.Contains(strings.ToLower(combinedStringData), "python") {
		fmt.Println("Python code detected. Analyzing...")
		decompiledFiles, err := analyzer.decompilePython(filePath)
		if err != nil {
			fmt.Printf("Error decompiling Python: %v\n", err)
			os.Exit(1)
		}

		defer cleanup(filePath, decompiledFiles)

		for _, filename := range decompiledFiles {
			outputName := strings.ReplaceAll(filename, " ", "_")
			fmt.Printf("Analyzing %s.py\n", outputName)

			content, err := ioutil.ReadFile(outputName + ".py")
			if err != nil {
				fmt.Printf("Error reading file %s: %v\n", outputName, err)
				continue
			}

			isMalware, err := analyzer.analyzeCode(string(content))
			if err != nil {
				fmt.Printf("Error analyzing code: %v\n", err)
				continue
			}
			fmt.Printf("Is malware: %v\n", isMalware)
		}
	} else {
		fmt.Println("No Malware code detected.")
	}
}
