package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Settings holds runtime configuration read from the environment. The Helm
// chart sets these from values.yaml; every variable has a safe default so the
// binary also runs outside the chart.
type Settings struct {
	// PodName identifies this pod in lock holder identities and logs.
	PodName string
	// Namespace is where the zone Leases and ConfigMaps live.
	Namespace string
	// OwnAcmeRecords makes the webhook authoritative for all
	// _acme-challenge TXT records in the zones it manages.
	OwnAcmeRecords bool
	// SweepInterval between periodic reconciles of all known zones. 0 disables.
	SweepInterval time.Duration
	// MaxRecordAge after which a desired record is dropped.
	MaxRecordAge time.Duration
	// LockWaitTimeout bounds how long a request waits for the zone lock.
	LockWaitTimeout time.Duration
	// LockDuration after which an unreleased zone lock is taken over.
	LockDuration time.Duration
	// TriggerContext enables the Challenge -> Order -> Certificate lookup
	// that names the certificate behind a request in the logs.
	TriggerContext bool
	// SerialCheck is "best-effort" (default), "required" or "off". It compares
	// the zone's SOA serial before the read and before the write; if the zone
	// changed in between, the write starts over from a fresh read.
	SerialCheck string
}

const (
	serialCheckBestEffort = "best-effort"
	serialCheckRequired   = "required"
	serialCheckOff        = "off"
)

const serviceAccountNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// loadSettings reads Settings from the environment.
func loadSettings() (Settings, error) {
	s := Settings{
		PodName:         os.Getenv("POD_NAME"),
		Namespace:       os.Getenv("POD_NAMESPACE"),
		OwnAcmeRecords:  true,
		SweepInterval:   15 * time.Minute,
		MaxRecordAge:    24 * time.Hour,
		LockWaitTimeout: 25 * time.Second,
		LockDuration:    60 * time.Second,
		TriggerContext:  true,
		SerialCheck:     serialCheckBestEffort,
	}
	if s.PodName == "" {
		s.PodName, _ = os.Hostname()
	}
	if s.Namespace == "" {
		if raw, err := os.ReadFile(serviceAccountNamespaceFile); err == nil {
			s.Namespace = strings.TrimSpace(string(raw))
		}
	}
	if s.Namespace == "" {
		return s, fmt.Errorf("POD_NAMESPACE is not set and %s is not readable", serviceAccountNamespaceFile)
	}

	var err error
	if s.OwnAcmeRecords, err = envBool("MIJN_HOST_OWN_ACME_RECORDS", s.OwnAcmeRecords); err != nil {
		return s, err
	}
	if s.SweepInterval, err = envDuration("MIJN_HOST_SWEEP_INTERVAL", s.SweepInterval); err != nil {
		return s, err
	}
	if s.MaxRecordAge, err = envDuration("MIJN_HOST_MAX_RECORD_AGE", s.MaxRecordAge); err != nil {
		return s, err
	}
	if s.LockWaitTimeout, err = envDuration("MIJN_HOST_LOCK_WAIT_TIMEOUT", s.LockWaitTimeout); err != nil {
		return s, err
	}
	if s.LockDuration, err = envDuration("MIJN_HOST_LOCK_DURATION", s.LockDuration); err != nil {
		return s, err
	}
	if s.TriggerContext, err = envBool("MIJN_HOST_TRIGGER_CONTEXT", s.TriggerContext); err != nil {
		return s, err
	}
	if v := os.Getenv("MIJN_HOST_SERIAL_CHECK"); v != "" {
		switch v {
		case serialCheckBestEffort, serialCheckRequired, serialCheckOff:
			s.SerialCheck = v
		default:
			return s, fmt.Errorf("MIJN_HOST_SERIAL_CHECK: %q is not one of best-effort, required, off", v)
		}
	}
	return s, nil
}

func envBool(name string, def bool) (bool, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", name, err)
	}
	return b, nil
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}
