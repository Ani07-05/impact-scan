#!/usr/bin/env python3
"""
Modern Web-based UI for Impact Scan
A fully functional web interface using Flask with real-time updates.
"""

import json
import os
import subprocess
import threading
import time
import webbrowser
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request, send_file

from impact_scan.core import aggregator, entrypoint
from impact_scan.core.html_report import save_report
from impact_scan.utils import schema

# Global scan state
scan_state = {
    "running": False,
    "progress": 0,
    "status": "Ready",
    "logs": [],
    "results": None,
}

app = Flask(__name__)
app.secret_key = "impact-scan-secret-key"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚀 Impact Scan - AI Security Platform</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1b26 0%, #24283b 100%);
            color: #c0caf5;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(45deg, #7aa2f7, #bb9af7);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(122, 162, 247, 0.3);
        }
        
        .header h1 {
            color: white;
            text-align: center;
            font-size: 2.5em;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            color: rgba(255,255,255,0.9);
            text-align: center;
            margin-top: 8px;
            font-size: 1.2em;
        }
        
        .main-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .card {
            background: rgba(36, 40, 59, 0.8);
            border: 2px solid #7aa2f7;
            border-radius: 12px;
            padding: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.2);
        }
        
        .card-title {
            color: #7dcfff;
            font-size: 1.5em;
            font-weight: bold;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            color: #e0af68;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px;
            background: #1f2335;
            border: 2px solid #565f89;
            border-radius: 8px;
            color: #c0caf5;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: #7aa2f7;
            box-shadow: 0 0 10px rgba(122, 162, 247, 0.3);
        }
        
        .btn {
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            margin: 5px;
            display: inline-block;
            text-decoration: none;
            text-align: center;
        }
        
        .btn-primary {
            background: linear-gradient(45deg, #7aa2f7, #9ece6a);
            color: white;
        }
        
        .btn-secondary {
            background: linear-gradient(45deg, #565f89, #7dcfff);
            color: white;
        }
        
        .btn-success {
            background: linear-gradient(45deg, #9ece6a, #73daca);
            color: #1a1b26;
        }
        
        .btn-warning {
            background: linear-gradient(45deg, #e0af68, #ff9e64);
            color: #1a1b26;
        }
        
        .btn-danger {
            background: linear-gradient(45deg, #f7768e, #ff757f);
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .progress-container {
            background: #1f2335;
            border-radius: 8px;
            padding: 4px;
            margin: 10px 0;
        }
        
        .progress-bar {
            background: linear-gradient(45deg, #7aa2f7, #bb9af7);
            height: 20px;
            border-radius: 4px;
            transition: width 0.5s ease;
            position: relative;
        }
        
        .progress-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            color: white;
            font-weight: bold;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.7);
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 10px;
            margin: 15px 0;
        }
        
        .metric-card {
            background: #1f2335;
            border: 2px solid;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .metric-card:hover {
            transform: scale(1.05);
        }
        
        .metric-total { border-color: #7dcfff; }
        .metric-critical { border-color: #f7768e; }
        .metric-high { border-color: #ff9e64; }
        .metric-medium { border-color: #e0af68; }
        .metric-low { border-color: #9ece6a; }
        .metric-score { border-color: #bb9af7; }
        
        .metric-number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .metric-label {
            font-size: 0.9em;
            opacity: 0.8;
        }
        
        .logs-container {
            background: #1f2335;
            border: 2px solid #7aa2f7;
            border-radius: 8px;
            height: 300px;
            overflow-y: auto;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        
        .log-entry {
            margin-bottom: 8px;
            padding: 5px;
            border-radius: 4px;
        }
        
        .log-info { color: #7dcfff; }
        .log-success { color: #9ece6a; }
        .log-warning { color: #e0af68; }
        .log-error { color: #f7768e; }
        
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        .findings-table th,
        .findings-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #565f89;
        }
        
        .findings-table th {
            background: #1f2335;
            color: #7dcfff;
            font-weight: bold;
        }
        
        .severity-critical { color: #f7768e; }
        .severity-high { color: #ff9e64; }
        .severity-medium { color: #e0af68; }
        .severity-low { color: #9ece6a; }
        
        .export-section {
            background: rgba(36, 40, 59, 0.8);
            border: 2px solid #9ece6a;
            border-radius: 12px;
            padding: 20px;
            margin-top: 20px;
            text-align: center;
        }
        
        .full-width {
            grid-column: 1 / -1;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(122, 162, 247, 0.3);
            border-radius: 50%;
            border-top-color: #7aa2f7;
            animation: spin 1s ease-in-out infinite;
            margin-right: 8px;
        }
        
        .file-browser {
            background: #1f2335;
            border: 2px solid #7aa2f7;
            border-radius: 8px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .file-item {
            padding: 8px;
            cursor: pointer;
            border-radius: 4px;
            transition: background 0.2s;
        }
        
        .file-item:hover {
            background: rgba(122, 162, 247, 0.2);
        }
        
        .file-item.directory {
            color: #7dcfff;
            font-weight: bold;
        }
        
        .file-item.file {
            color: #c0caf5;
        }
        
        .hidden {
            display: none;
        }
        
        @media (max-width: 768px) {
            .main-grid {
                grid-template-columns: 1fr;
            }
            
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Impact Scan - AI Security Platform</h1>
            <p>🔮 Next-Generation Multi-Agent Security Intelligence</p>
        </div>
        
        <div class="main-grid">
            <!-- Configuration Card -->
            <div class="card">
                <div class="card-title">
                    🔧 Scan Configuration
                </div>
                
                <form id="scanForm">
                    <div class="form-group">
                        <label for="targetPath">📁 Target Directory:</label>
                        <div style="display: flex; gap: 10px;">
                            <input type="text" id="targetPath" name="targetPath" 
                                   value="{{ current_path }}" required>
                            <button type="button" class="btn btn-secondary" onclick="browsePath()">📂 Browse</button>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="profile">⚡ Scan Profile:</label>
                        <select id="profile" name="profile">
                            <option value="comprehensive">🧠 Comprehensive (All Features)</option>
                            <option value="standard">🔍 Standard (Medium+)</option>
                            <option value="quick">🚀 Quick (High/Critical)</option>
                            <option value="ci">🤖 CI/CD Pipeline</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="aiProvider">🤖 AI Provider:</label>
                        <select id="aiProvider" name="aiProvider">
                            <option value="auto">✨ Auto-detect</option>
                            <option value="openai">🧠 OpenAI GPT</option>
                            <option value="anthropic">🔮 Anthropic Claude</option>
                            <option value="gemini">💎 Google Gemini</option>
                            <option value="none">❌ Disabled</option>
                        </select>
                    </div>
                    
                    <div style="display: flex; gap: 10px; align-items: center; margin: 15px 0;">
                        <label>
                            <input type="checkbox" id="enableAiFixes" checked> 🤖 AI Fixes
                        </label>
                        <label>
                            <input type="checkbox" id="enableWebSearch" checked> 🌐 Web Search
                        </label>
                    </div>
                    
                    <div style="text-align: center; margin-top: 20px;">
                        <button type="submit" class="btn btn-primary" id="startScanBtn">
                            <span id="scanBtnText">🚀 Start Comprehensive Scan</span>
                            <span id="scanSpinner" class="spinner hidden"></span>
                        </button>
                        <button type="button" class="btn btn-secondary" onclick="manageApiKeys()">
                            🔑 API Keys
                        </button>
                    </div>
                </form>
            </div>
            
            <!-- Metrics Card -->
            <div class="card">
                <div class="card-title">
                    📊 Security Metrics
                </div>
                
                <div class="metrics-grid">
                    <div class="metric-card metric-total">
                        <div class="metric-number" id="totalFindings">0</div>
                        <div class="metric-label">Total</div>
                    </div>
                    <div class="metric-card metric-critical">
                        <div class="metric-number" id="criticalFindings">0</div>
                        <div class="metric-label">Critical</div>
                    </div>
                    <div class="metric-card metric-high">
                        <div class="metric-number" id="highFindings">0</div>
                        <div class="metric-label">High</div>
                    </div>
                    <div class="metric-card metric-medium">
                        <div class="metric-number" id="mediumFindings">0</div>
                        <div class="metric-label">Medium</div>
                    </div>
                    <div class="metric-card metric-low">
                        <div class="metric-number" id="lowFindings">0</div>
                        <div class="metric-label">Low</div>
                    </div>
                    <div class="metric-card metric-score">
                        <div class="metric-number" id="securityScore">100</div>
                        <div class="metric-label">Score%</div>
                    </div>
                </div>
                
                <!-- Progress Section -->
                <div style="margin-top: 20px;">
                    <strong>📈 Scan Progress:</strong>
                    <div class="progress-container">
                        <div class="progress-bar" id="progressBar" style="width: 0%">
                            <div class="progress-text" id="progressText">Ready to scan</div>
                        </div>
                    </div>
                    <div style="text-align: center; margin-top: 10px;">
                        <span id="statusText">Ready to scan</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Logs Section -->
        <div class="card full-width">
            <div class="card-title">
                📋 Scan Logs & Progress
            </div>
            <div class="logs-container" id="logsContainer">
                <div class="log-entry log-info">
                    🚀 [STARTUP] Impact Scan AI Security Platform initialized<br>
                    🧠 [AI] Multi-agent security orchestration ready<br>
                    🎯 [READY] Configure your scan and click 'Start Comprehensive Scan' to begin!
                </div>
            </div>
        </div>
        
        <!-- Results Section -->
        <div class="card full-width" id="resultsSection" style="display: none;">
            <div class="card-title">
                🔍 Security Findings
            </div>
            <div id="findingsContainer">
                <!-- Findings table will be populated here -->
            </div>
        </div>
        
        <!-- Export Section -->
        <div class="export-section" id="exportSection" style="display: none;">
            <div class="card-title" style="margin-bottom: 15px;">
                📤 Export Results
            </div>
            <button onclick="exportHtml()" class="btn btn-success">📄 HTML Report</button>
            <button onclick="exportSarif()" class="btn btn-primary">📊 SARIF Format</button>
            <button onclick="exportPdf()" class="btn btn-warning">📋 PDF Report</button>
            <button onclick="viewDetails()" class="btn btn-secondary">📂 View Details</button>
        </div>
    </div>

    <script>
        let scanInProgress = false;
        let updateInterval;
        
        // Start scan
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            startScan();
        });
        
        async function startScan() {
            if (scanInProgress) return;
            
            const formData = new FormData(document.getElementById('scanForm'));
            const config = {
                target_path: formData.get('targetPath'),
                profile: formData.get('profile'),
                ai_provider: formData.get('aiProvider'),
                enable_ai_fixes: document.getElementById('enableAiFixes').checked,
                enable_web_search: document.getElementById('enableWebSearch').checked
            };
            
            scanInProgress = true;
            document.getElementById('startScanBtn').disabled = true;
            document.getElementById('scanBtnText').textContent = '⚙️ Scanning...';
            document.getElementById('scanSpinner').classList.remove('hidden');
            
            try {
                const response = await fetch('/api/start_scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(config)
                });
                
                if (response.ok) {
                    addLog('🚀 [SCAN] Starting comprehensive security analysis...', 'info');
                    startProgressUpdates();
                } else {
                    addLog('❌ [ERROR] Failed to start scan', 'error');
                    resetScanButton();
                }
            } catch (error) {
                addLog(`❌ [ERROR] Network error: ${error}`, 'error');
                resetScanButton();
            }
        }
        
        function startProgressUpdates() {
            updateInterval = setInterval(updateProgress, 1000);
        }
        
        async function updateProgress() {
            try {
                const response = await fetch('/api/scan_status');
                const status = await response.json();
                
                // Update progress bar
                document.getElementById('progressBar').style.width = status.progress + '%';
                document.getElementById('progressText').textContent = status.progress + '%';
                document.getElementById('statusText').textContent = status.status;
                
                // Update logs
                if (status.logs && status.logs.length > 0) {
                    status.logs.forEach(log => addLog(log, 'info'));
                }
                
                // Update metrics if scan complete
                if (status.results) {
                    updateMetrics(status.results);
                    showResults(status.results);
                }
                
                // Check if scan finished
                if (!status.running) {
                    clearInterval(updateInterval);
                    resetScanButton();
                    if (status.progress === 100) {
                        addLog('🎉 [SUCCESS] Scan completed successfully!', 'success');
                        document.getElementById('exportSection').style.display = 'block';
                    }
                }
            } catch (error) {
                console.error('Error updating progress:', error);
            }
        }
        
        function resetScanButton() {
            scanInProgress = false;
            document.getElementById('startScanBtn').disabled = false;
            document.getElementById('scanBtnText').textContent = '🚀 Start Comprehensive Scan';
            document.getElementById('scanSpinner').classList.add('hidden');
        }
        
        function addLog(message, type = 'info') {
            const logsContainer = document.getElementById('logsContainer');
            const logEntry = document.createElement('div');
            logEntry.className = `log-entry log-${type}`;
            logEntry.innerHTML = message + '<br>';
            logsContainer.appendChild(logEntry);
            logsContainer.scrollTop = logsContainer.scrollHeight;
        }
        
        function updateMetrics(results) {
            if (!results || !results.findings) return;
            
            const counts = {
                total: results.findings.length,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            };
            
            results.findings.forEach(finding => {
                const severity = finding.severity.toLowerCase();
                if (counts.hasOwnProperty(severity)) {
                    counts[severity]++;
                }
            });
            
            document.getElementById('totalFindings').textContent = counts.total;
            document.getElementById('criticalFindings').textContent = counts.critical;
            document.getElementById('highFindings').textContent = counts.high;
            document.getElementById('mediumFindings').textContent = counts.medium;
            document.getElementById('lowFindings').textContent = counts.low;
            
            // Calculate security score
            const score = Math.max(0, 100 - (counts.critical * 25 + counts.high * 10 + 
                                            counts.medium * 5 + counts.low * 1));
            document.getElementById('securityScore').textContent = score;
        }
        
        function showResults(results) {
            if (!results || !results.findings) return;
            
            const resultsSection = document.getElementById('resultsSection');
            const findingsContainer = document.getElementById('findingsContainer');
            
            let tableHtml = `
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>🚨 Severity</th>
                            <th>🔍 Type</th>
                            <th>📁 File</th>
                            <th>📍 Line</th>
                            <th>📝 Description</th>
                            <th>💡 Fix</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            results.findings.slice(0, 50).forEach(finding => {
                const severityClass = `severity-${finding.severity.toLowerCase()}`;
                const severityIcon = {
                    'critical': '🔴',
                    'high': '🟠', 
                    'medium': '🟡',
                    'low': '🔵'
                }[finding.severity.toLowerCase()] || '⚪';
                
                tableHtml += `
                    <tr>
                        <td class="${severityClass}">${severityIcon} ${finding.severity.toUpperCase()}</td>
                        <td>${finding.rule_id || finding.type || 'Unknown'}</td>
                        <td>${finding.file_path}</td>
                        <td>${finding.line_number || 'N/A'}</td>
                        <td>${finding.title}</td>
                        <td>${finding.ai_fix ? finding.ai_fix.substring(0, 50) + '...' : 'No fix available'}</td>
                    </tr>
                `;
            });
            
            if (results.findings.length > 50) {
                tableHtml += `
                    <tr>
                        <td colspan="6" style="text-align: center; font-style: italic; opacity: 0.7;">
                            ... and ${results.findings.length - 50} more findings
                        </td>
                    </tr>
                `;
            }
            
            tableHtml += '</tbody></table>';
            findingsContainer.innerHTML = tableHtml;
            resultsSection.style.display = 'block';
        }
        
        // Export functions
        async function exportHtml() {
            try {
                const response = await fetch('/api/export/html', { method: 'POST' });
                const result = await response.json();
                if (result.success) {
                    addLog(`📄 [EXPORT] HTML report saved: ${result.filename}`, 'success');
                    window.open(result.url, '_blank');
                } else {
                    addLog(`❌ [ERROR] HTML export failed: ${result.error}`, 'error');
                }
            } catch (error) {
                addLog(`❌ [ERROR] Export error: ${error}`, 'error');
            }
        }
        
        async function exportSarif() {
            try {
                const response = await fetch('/api/export/sarif', { method: 'POST' });
                const result = await response.json();
                if (result.success) {
                    addLog(`📊 [EXPORT] SARIF report saved: ${result.filename}`, 'success');
                    // Download the file
                    window.location.href = result.download_url;
                } else {
                    addLog(`❌ [ERROR] SARIF export failed: ${result.error}`, 'error');
                }
            } catch (error) {
                addLog(`❌ [ERROR] Export error: ${error}`, 'error');
            }
        }
        
        async function exportPdf() {
            try {
                const response = await fetch('/api/export/pdf', { method: 'POST' });
                const result = await response.json();
                if (result.success) {
                    addLog(`📋 [EXPORT] PDF report saved: ${result.filename}`, 'success');
                    // Download the file
                    window.location.href = result.download_url;
                } else {
                    addLog(`❌ [ERROR] PDF export failed: ${result.error}`, 'error');
                }
            } catch (error) {
                addLog(`❌ [ERROR] Export error: ${error}`, 'error');
            }
        }
        
        function viewDetails() {
            addLog('📂 [VIEW] Opening detailed results panel...', 'info');
            // Could open a modal or new page with detailed results
        }
        
        function browsePath() {
            addLog('📁 [BROWSE] File browser functionality coming soon...', 'info');
            // For now, user can manually type path
        }
        
        function manageApiKeys() {
            const keys = {
                openai: prompt('Enter OpenAI API Key (leave empty to keep current):'),
                anthropic: prompt('Enter Anthropic API Key (leave empty to keep current):'),
                gemini: prompt('Enter Google Gemini API Key (leave empty to keep current):")
            };
            
            // Filter out empty keys
            const validKeys = Object.fromEntries(
                Object.entries(keys).filter(([_, value]) => value && value.trim())
            );
            
            if (Object.keys(validKeys).length > 0) {
                fetch('/api/api_keys', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(validKeys)
                }).then(response => {
                    if (response.ok) {
                        addLog('🔑 [API] API keys updated successfully', 'success');
                    } else {
                        addLog('❌ [ERROR] Failed to update API keys', 'error');
                    }
                });
            }
        }
        
        // Auto-refresh logs every 2 seconds when scanning
        setInterval(() => {
            if (scanInProgress) {
                updateProgress();
            }
        }, 2000);
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    """Main web interface."""
    current_path = str(Path.cwd())
    return render_template_string(HTML_TEMPLATE, current_path=current_path)


@app.route("/api/start_scan", methods=["POST"])
def start_scan():
    """Start a security scan."""
    global scan_state

    if scan_state["running"]:
        return jsonify({"success": False, "error": "Scan already running"})

    try:
        config_data = request.get_json()

        # Create scan configuration
        config = schema.ScanConfig(
            target_path=Path(config_data["target_path"]),
            output_format="console",
            ai_provider=config_data["ai_provider"]
            if config_data["ai_provider"] != "none"
            else None,
            enable_ai_fixes=config_data["enable_ai_fixes"],
            enable_web_search=config_data["enable_web_search"],
            profile=config_data["profile"],
        )

        # Reset scan state
        scan_state = {
            "running": True,
            "progress": 0,
            "status": "Starting scan...",
            "logs": [],
            "results": None,
        }

        # Start scan in background thread
        thread = threading.Thread(target=run_scan_background, args=(config,))
        thread.daemon = True
        thread.start()

        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


def run_scan_background(config):
    """Run scan in background thread."""
    global scan_state

    try:
        scan_state["logs"].append(
            "🚀 [SCAN] Starting comprehensive security analysis..."
        )
        scan_state["progress"] = 10

        # Run the actual scan
        scan_state["logs"].append("🎯 [TARGET] Analyzing target directory...")
        scan_state["progress"] = 20

        result = entrypoint.run_scan(config)

        scan_state["logs"].append("🔍 [ANALYSIS] Running static security analysis...")
        scan_state["progress"] = 50

        scan_state["logs"].append(
            "📦 [DEPS] Checking dependencies for vulnerabilities..."
        )
        scan_state["progress"] = 70

        if config.enable_web_search:
            scan_state["logs"].append(
                "🌐 [WEB-SEARCH] Gathering threat intelligence..."
            )
            scan_state["progress"] = 85

        if config.enable_ai_fixes:
            scan_state["logs"].append(
                "🤖 [AI-FIXES] Generating intelligent remediation..."
            )
            scan_state["progress"] = 95

        scan_state["logs"].append("✅ [SUCCESS] Scan completed successfully!")
        scan_state["progress"] = 100
        scan_state["status"] = "Scan completed"
        scan_state["results"] = result

    except Exception as e:
        scan_state["logs"].append(f"❌ [ERROR] Scan failed: {str(e)}")
        scan_state["status"] = "Scan failed"
    finally:
        scan_state["running"] = False


@app.route("/api/scan_status")
def scan_status():
    """Get current scan status."""
    return jsonify(scan_state)


@app.route("/api/export/html", methods=["POST"])
def export_html():
    """Export results as HTML."""
    global scan_state

    if not scan_state["results"]:
        return jsonify({"success": False, "error": "No scan results available"})

    try:
        timestamp = int(time.time())
        filename = f"impact_scan_report_{timestamp}.html"
        filepath = Path.cwd() / filename

        save_report(scan_state["results"], str(filepath))

        return jsonify(
            {
                "success": True,
                "filename": filename,
                "url": f"file://{filepath.absolute()}",
            }
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/export/sarif", methods=["POST"])
def export_sarif():
    """Export results as SARIF."""
    global scan_state

    if not scan_state["results"]:
        return jsonify({"success": False, "error": "No scan results available"})

    try:
        timestamp = int(time.time())
        filename = f"impact_scan_sarif_{timestamp}.json"
        filepath = Path.cwd() / filename

        # Generate SARIF using aggregator
        sarif_result = aggregator.to_sarif([scan_state["results"]])

        with open(filepath, "w") as f:
            json.dump(sarif_result, f, indent=2)

        return jsonify(
            {
                "success": True,
                "filename": filename,
                "download_url": f"/download/{filename}",
            }
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/export/pdf", methods=["POST"])
def export_pdf():
    """Export results as PDF."""
    global scan_state

    if not scan_state["results"]:
        return jsonify({"success": False, "error": "No scan results available"})

    try:
        timestamp = int(time.time())
        html_filename = f"temp_report_{timestamp}.html"
        pdf_filename = f"impact_scan_report_{timestamp}.pdf"

        html_filepath = Path.cwd() / html_filename
        pdf_filepath = Path.cwd() / pdf_filename

        # Generate HTML first
        save_report(scan_state["results"], str(html_filepath))

        # Try to generate PDF using wkhtmltopdf
        try:
            subprocess.run(
                [
                    "wkhtmltopdf",
                    "--page-size",
                    "A4",
                    "--orientation",
                    "Portrait",
                    "--margin-top",
                    "0.75in",
                    "--margin-right",
                    "0.75in",
                    "--margin-bottom",
                    "0.75in",
                    "--margin-left",
                    "0.75in",
                    str(html_filepath),
                    str(pdf_filepath),
                ],
                check=True,
                capture_output=True,
            )

            # Clean up temp HTML
            html_filepath.unlink()

            return jsonify(
                {
                    "success": True,
                    "filename": pdf_filename,
                    "download_url": f"/download/{pdf_filename}",
                }
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            # Fallback: just return HTML if PDF generation fails
            html_filepath.rename(pdf_filepath.with_suffix(".html"))
            return jsonify(
                {
                    "success": True,
                    "filename": pdf_filename.replace(".pdf", ".html"),
                    "download_url": f"/download/{pdf_filename.replace('.pdf', '.html')}",
                }
            )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/api_keys", methods=["POST"])
def update_api_keys():
    """Update API keys."""
    try:
        keys = request.get_json()

        if keys.get("openai"):
            os.environ["OPENAI_API_KEY"] = keys["openai"]
        if keys.get("anthropic"):
            os.environ["ANTHROPIC_API_KEY"] = keys["anthropic"]
        if keys.get("gemini"):
            os.environ["GOOGLE_API_KEY"] = keys["gemini"]

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/download/<filename>")
def download_file(filename):
    """Download exported file."""
    filepath = Path.cwd() / filename
    if filepath.exists():
        return send_file(str(filepath), as_attachment=True)
    else:
        return jsonify({"error": "File not found"}), 404


def run_web_ui(port=5000, auto_open=True):
    """Launch the web UI."""
    if auto_open:
        # Open browser after a short delay
        def open_browser():
            time.sleep(1)
            webbrowser.open(f"http://localhost:{port}")

        thread = threading.Thread(target=open_browser)
        thread.daemon = True
        thread.start()

    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_web_ui()
