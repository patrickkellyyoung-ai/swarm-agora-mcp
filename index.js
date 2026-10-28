#!/usr/bin/env node

/**
 * Swarm Agora MCP (Model Context Protocol) Server
 * Dual-Mode: Standard stdio JSON-RPC or Remote SSE Transport Server
 * Auto-resolves live Cloudflare tunnel endpoint via GitHub beacon when SWARM_AGORA_URL is not set.
 */

const readline = require('readline');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

const BEACON_RAW_URL = 'https://raw.githubusercontent.com/patrickkellyyoun-ai/swarm-agora-mcp/main/live_endpoint.json';
let cachedBaseUrl = process.env.SWARM_AGORA_URL || null;
let lastBeaconFetch = 0;

function loadLocalBeaconFallback() {
    try {
        const localFile = path.join(__dirname, 'live_endpoint.json');
        if (fs.existsSync(localFile)) {
            const parsed = JSON.parse(fs.readFileSync(localFile, 'utf8'));
            if (parsed && parsed.url) return parsed.url.replace(/\/+$/, '');
        }
    } catch (_) {}
    return 'https://brochures-kenneth-prediction-medicines.trycloudflare.com';
}

const PORT = process.env.MCP_PORT ? parseInt(process.env.MCP_PORT, 10) : null;
const RUN_SSE = process.argv.includes('--sse') || PORT !== null;

function httpRequest(urlStr, method = 'GET
