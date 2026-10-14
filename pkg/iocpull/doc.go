// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - IOC Pull from Platform
// =========================================================================
//
// Package iocpull provides opt-in IOC (Indicator of Compromise) pull from
// AegisGate Platform. It allows Rampart to fetch IOC fingerprints published
// by the Platform and use them to augment local detection capabilities.
//
// # Air-gap Compatible
//
// IOC pull is entirely opt-in. An empty platform_url means no pull occurs;
// Rampart continues to function fully with local detections only.
// No data leaves the system, no background connections are made.
//
// # What Is Pulled
//
// The pull endpoint (GET /api/v1/ioc/latest) returns IOC fingerprints.
// Each fingerprint is a SHA-256 hash of a detected pattern. No PII, no
// prompt text, no user data is ever exchanged — only cryptographic hashes
// and metadata (rule ID, severity, category, peer count, timestamps).
//
// # Bandwidth Efficiency
//
// The puller uses the If-Modified-Since header so the Platform can respond
// with HTTP 304 (Not Modified) when no new IOCs are available. This keeps
// recurring poll traffic to a minimum — ideal for low-bandwidth or
// metered environments.
//
// # Authentication
//
// When an API key is configured, requests include:
//
//	Authorization: Bearer <api-key>
//
// # Privacy
//
// IOC fingerprints are SHA-256 hashes — no PII, no prompt text, no
// credentials. The pull direction only brings hashes INTO Rampart;
// it does not send any local data to the Platform. This preserves all
// 12 non-negotiable privacy principles.
//
// =========================================================================
package iocpull
