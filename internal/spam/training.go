package spam

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

// TrainingManager manages spam filter training from user feedback.
// It accepts anonymized feature vectors (hashed word frequencies) to prevent
// the server from learning plaintext content.
//
// Anti-poisoning: a minimum number of independent users (consensusThreshold)
// must report the same feature pattern before it is applied to the model.
type TrainingManager struct {
	classifier *BayesClassifier
	mu         sync.Mutex

	// Rate limiting per user: max trainingSamples per window.
	userCounts map[string]int
	maxPerUser int

	// Consensus tracking: require N independent users to agree.
	consensusThreshold int
	pendingReports     map[string]*pendingReport // keyed by feature fingerprint

	// Track total samples for periodic sealing.
	totalSamples atomic.Int64
	sealEvery    int64
}

// pendingReport tracks how many distinct users have flagged a feature set.
type pendingReport struct {
	features map[string]float64
	isSpam   bool
	users    map[string]bool
}

// NewTrainingManager creates a new TrainingManager.
// consensusThreshold is the minimum number of independent users required
// before feedback is applied to the model (minimum 1).
func NewTrainingManager(classifier *BayesClassifier, maxPerUser int, sealEvery int64) *TrainingManager {
	return &TrainingManager{
		classifier:         classifier,
		userCounts:         make(map[string]int),
		maxPerUser:         maxPerUser,
		sealEvery:          sealEvery,
		consensusThreshold: 3,
		pendingReports:     make(map[string]*pendingReport),
	}
}

// TrainFromFeedback records user feedback and applies it to the model only
// when consensusThreshold independent users have reported the same pattern.
// The features should be hashed word frequency vectors, not plaintext.
// Returns an error if the user has exceeded their training rate limit.
func (tm *TrainingManager) TrainFromFeedback(userID string, features map[string]float64, isSpam bool) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	count := tm.userCounts[userID]
	if count >= tm.maxPerUser {
		return fmt.Errorf("training rate limit exceeded for user")
	}
	tm.userCounts[userID] = count + 1

	// Compute a fingerprint of the feature set for consensus tracking.
	fp := featureFingerprint(features, isSpam)

	report, exists := tm.pendingReports[fp]
	if !exists {
		report = &pendingReport{
			features: features,
			isSpam:   isSpam,
			users:    make(map[string]bool),
		}
		tm.pendingReports[fp] = report
	}

	report.users[userID] = true

	// Only apply when enough independent users agree.
	if len(report.users) >= tm.consensusThreshold {
		tm.classifier.Train(features, isSpam)
		tm.totalSamples.Add(1)
		delete(tm.pendingReports, fp)
	}

	return nil
}

// featureFingerprint returns a stable hash of the feature keys and spam label.
func featureFingerprint(features map[string]float64, isSpam bool) string {
	keys := make([]string, 0, len(features))
	for k := range features {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
	}
	if isSpam {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ResetRateLimits clears per-user training rate limits (call periodically).
func (tm *TrainingManager) ResetRateLimits() {
	tm.mu.Lock()
	tm.userCounts = make(map[string]int)
	tm.mu.Unlock()
}

// ShouldSeal returns true if enough samples have been collected to warrant
// sealing the model in the TEE.
func (tm *TrainingManager) ShouldSeal() bool {
	if tm.sealEvery <= 0 {
		return false
	}
	return tm.totalSamples.Load()%tm.sealEvery == 0 && tm.totalSamples.Load() > 0
}

// TotalSamples returns the total number of training samples processed.
func (tm *TrainingManager) TotalSamples() int64 {
	return tm.totalSamples.Load()
}

// AnonymizeFeatures takes raw features and returns hashed versions.
// This ensures the training pipeline never sees plaintext words.
func AnonymizeFeatures(features map[string]float64) map[string]float64 {
	anon := make(map[string]float64, len(features))
	for word, freq := range features {
		h := sha256.Sum256([]byte(word))
		key := fmt.Sprintf("%x", h[:8]) // 16-char hex prefix
		anon[key] += freq
	}
	return anon
}
