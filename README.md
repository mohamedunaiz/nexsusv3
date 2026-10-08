# CyberResearch-X — NEXSUS SOC Command Center v3

> **An AI-assisted SOC platform with a React/Vite frontend and Python/FastAPI security backend.**

[![Frontend](https://img.shields.io/badge/Frontend-Vite%20%2B%20React-646CFF)](#)
[![Backend](https://img.shields.io/badge/Backend-Python%20%2B%20FastAPI-009688)](#)
[![Security](https://img.shields.io/badge/Focus-SOC%20%2B%20Threat%20Intel-red)](#)
[![Malware Intelligence](https://img.shields.io/badge/Engine-Malware%20Intelligence-purple)](#)

## Overview

NEXSUS v3 is the Python/FastAPI evolution of NEXSUS. It combines SOC dashboarding, case/IOC management, AI-assisted investigation, specialist agents, malware intelligence, PCAP metadata analysis, knowledge extraction and evidence fusion.

The architecture deliberately separates **measurable malware evidence from LLM reasoning**.

## Malware Intelligence Engine

**Evidence Intake → Static Features → Rule Engine → Similarity Engine → Baseline Classifier → Knowledge Extraction → Evidence Fusion → Verdict**

The design principle is:

**The LLM is not the detector.**

The backend first produces structured evidence such as hashes, entropy, PE/ELF metadata, rule hits, similarity scores and classifier probabilities. The agent layer reasons over that structured output.

## PCAP Boundary

PCAP uploads are decoded passively. The application can extract packet counts, endpoints, ports, DNS names, HTTP Host values and TLS SNI metadata.

Dynamic sandbox execution is intentionally outside the application boundary and requires an isolated external adapter.

## Architecture

**Analyst → React/Vite → FastAPI → Authentication / SOC / Cases / IOCs / Malware Intelligence / PCAP / Knowledge / AI**

## Local Development

Frontend:

    npm install
    npm run dev

Backend:

    cd python-server
    pip install -r requirements.txt
    python -m uvicorn app.main:app --reload --port 8000

## Environment

- GEMINI_API_KEY
- JWT_SECRET
- CSRF_SECRET
- TOOL_ENCRYPTION_KEY
- ADMIN_INITIAL_PASSWORD
- ANALYST_INITIAL_PASSWORD
- VIEWER_INITIAL_PASSWORD

Never commit real .env files or secrets.

## Verification

    npm test
    npm run typecheck
    cd python-server
    python -m pytest -q

## Production Security

Before deployment:

1. Set strong secrets.
2. Configure operator passwords.
3. Verify authentication and authorization.
4. Review allowed origins.
5. Confirm tool credentials are encrypted.
6. Verify security-audit results.
7. Keep external sandbox execution disabled unless an isolated reviewed adapter is deployed.

## Security Philosophy

**Evidence → analysis → correlation → analyst validation → response**

## Author

**Mohamed Unaiz** — Cybersecurity • SOC • Threat Intelligence • Malware Analysis • AI Security