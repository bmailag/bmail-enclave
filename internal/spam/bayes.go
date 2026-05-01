package spam

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
)

// checksumSize is the length of the SHA-256 integrity checksum appended to serialized data.
const checksumSize = sha256.Size

// BayesClassifier implements a naive Bayes spam classifier using word frequencies.
type BayesClassifier struct {
	mu        sync.RWMutex
	SpamWords map[string]float64 // word -> count in spam corpus
	HamWords  map[string]float64 // word -> count in ham corpus
	SpamTotal float64            // total words seen in spam
	HamTotal  float64            // total words seen in ham
	SpamDocs  float64            // number of spam documents trained
	HamDocs   float64            // number of ham documents trained
}

// NewBayesClassifier creates a new empty Bayes classifier.
func NewBayesClassifier() *BayesClassifier {
	return &BayesClassifier{
		SpamWords: make(map[string]float64),
		HamWords:  make(map[string]float64),
	}
}

// maxVocabSize caps the number of unique words per class to prevent unbounded memory growth.
const maxVocabSize = 500000

// vocabSaturationWarned ensures the saturation warning is logged only once.
var vocabSaturationWarned atomic.Bool

// Train updates the classifier with a set of features extracted from a message.
func (bc *BayesClassifier) Train(features map[string]float64, isSpam bool) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if isSpam {
		bc.SpamDocs++
		for word, freq := range features {
			if _, exists := bc.SpamWords[word]; !exists && len(bc.SpamWords) >= maxVocabSize {
				if vocabSaturationWarned.CompareAndSwap(false, true) {
					slog.Warn("bayesian spam vocab saturated, new words being dropped", "class", "spam", "max_vocab", maxVocabSize)
				}
				continue
			}
			bc.SpamWords[word] += freq
			bc.SpamTotal += freq
		}
	} else {
		bc.HamDocs++
		for word, freq := range features {
			if _, exists := bc.HamWords[word]; !exists && len(bc.HamWords) >= maxVocabSize {
				if vocabSaturationWarned.CompareAndSwap(false, true) {
					slog.Warn("bayesian ham vocab saturated, new words being dropped", "class", "ham", "max_vocab", maxVocabSize)
				}
				continue
			}
			bc.HamWords[word] += freq
			bc.HamTotal += freq
		}
	}
}

// Predict returns the probability (0-1) that the given features represent spam.
// Uses log-space computation to avoid floating-point underflow.
func (bc *BayesClassifier) Predict(features map[string]float64) float64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	totalDocs := bc.SpamDocs + bc.HamDocs
	if totalDocs == 0 {
		return 0.5 // No training data — uninformative prior
	}

	// Prior probabilities (with Laplace smoothing).
	logPriorSpam := math.Log((bc.SpamDocs + 1) / (totalDocs + 2))
	logPriorHam := math.Log((bc.HamDocs + 1) / (totalDocs + 2))

	logLikelihoodSpam := logPriorSpam
	logLikelihoodHam := logPriorHam

	// Vocabulary size for Laplace smoothing.
	vocab := make(map[string]bool)
	for w := range bc.SpamWords {
		vocab[w] = true
	}
	for w := range bc.HamWords {
		vocab[w] = true
	}
	vocabSize := float64(len(vocab))
	if vocabSize == 0 {
		vocabSize = 1
	}

	for word, freq := range features {
		// P(word | spam) with Laplace smoothing.
		spamCount := bc.SpamWords[word]
		hamCount := bc.HamWords[word]

		pWordSpam := (spamCount + 1) / (bc.SpamTotal + vocabSize)
		pWordHam := (hamCount + 1) / (bc.HamTotal + vocabSize)

		logLikelihoodSpam += freq * math.Log(pWordSpam)
		logLikelihoodHam += freq * math.Log(pWordHam)
	}

	// Convert from log-space using the log-sum-exp trick.
	maxLog := logLikelihoodSpam
	if logLikelihoodHam > maxLog {
		maxLog = logLikelihoodHam
	}

	expSpam := math.Exp(logLikelihoodSpam - maxLog)
	expHam := math.Exp(logLikelihoodHam - maxLog)

	prob := expSpam / (expSpam + expHam)

	// Clamp to [0, 1].
	if prob < 0 {
		prob = 0
	}
	if prob > 1 {
		prob = 1
	}

	return prob
}

// Serialize encodes the classifier model to bytes with a SHA-256 integrity checksum.
// The checksum is appended as the last 32 bytes to detect accidental corruption.
// SHA-256 detects accidental corruption. Deliberate tampering is mitigated by
// running the classifier inside the SGX enclave (memory encryption + attestation).
func (bc *BayesClassifier) Serialize() ([]byte, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	data := bayesData{
		SpamWords: bc.SpamWords,
		HamWords:  bc.HamWords,
		SpamTotal: bc.SpamTotal,
		HamTotal:  bc.HamTotal,
		SpamDocs:  bc.SpamDocs,
		HamDocs:   bc.HamDocs,
	}

	if err := enc.Encode(data); err != nil {
		return nil, err
	}

	gobBytes := buf.Bytes()
	checksum := sha256.Sum256(gobBytes)
	return append(gobBytes, checksum[:]...), nil
}

// Deserialize loads classifier model from bytes, verifying the SHA-256 integrity checksum.
// SHA-256 detects accidental corruption. Deliberate tampering is mitigated by
// running the classifier inside the SGX enclave (memory encryption + attestation).
func (bc *BayesClassifier) Deserialize(b []byte) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if len(b) < checksumSize {
		return fmt.Errorf("bayes data too short: missing integrity checksum")
	}

	gobBytes := b[:len(b)-checksumSize]
	storedChecksum := b[len(b)-checksumSize:]
	computed := sha256.Sum256(gobBytes)
	if !bytes.Equal(computed[:], storedChecksum) {
		return fmt.Errorf("bayes data integrity check failed: checksum mismatch")
	}

	var data bayesData
	dec := gob.NewDecoder(bytes.NewReader(gobBytes))
	if err := dec.Decode(&data); err != nil {
		return err
	}

	bc.SpamWords = data.SpamWords
	bc.HamWords = data.HamWords
	bc.SpamTotal = data.SpamTotal
	bc.HamTotal = data.HamTotal
	bc.SpamDocs = data.SpamDocs
	bc.HamDocs = data.HamDocs

	return nil
}

// bayesData is the serialization format for the classifier.
type bayesData struct {
	SpamWords map[string]float64
	HamWords  map[string]float64
	SpamTotal float64
	HamTotal  float64
	SpamDocs  float64
	HamDocs   float64
}

// wordRegex matches sequences of letters and digits (word tokens).
var wordRegex = regexp.MustCompile(`[a-zA-Z0-9]+`)

// ExtractFeatures tokenizes a message body and returns word frequency counts.
// Processing is capped to prevent resource exhaustion on large messages.
func ExtractFeatures(body []byte) map[string]float64 {
	features := make(map[string]float64)

	// Cap input to 1MB to prevent excessive memory use on large messages.
	if len(body) > 1024*1024 {
		body = body[:1024*1024]
	}

	// Convert to lowercase string and extract words.
	text := strings.ToLower(string(body))

	// Strip HTML tags.
	text = stripHTML(text)

	tokens := wordRegex.FindAllString(text, 50000)
	for _, token := range tokens {
		// Skip very short or very long tokens.
		if len(token) < 2 || len(token) > 30 {
			continue
		}
		// Skip pure numbers.
		if isAllDigits(token) {
			continue
		}
		features[token] += 1.0
	}

	return features
}

// stripHTML removes HTML tags from text.
func stripHTML(s string) string {
	var result strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
			result.WriteRune(' ')
		case !inTag:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// isAllDigits returns true if the string is composed entirely of digits.
func isAllDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
