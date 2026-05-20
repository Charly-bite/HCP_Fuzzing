package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	fuzzerDir  = "/cluster_data/fuzzer"
	logDir     = "/cluster_data/fuzz_logs"
	runScript  = "/cluster_data/fuzzer/run_fuzz.sh"
	llmBinary  = "/cluster_data/llama.cpp/build/bin/llama-cli"
	llmModel   = "/cluster_data/models/Meta-Llama-3-8B-Instruct-Q4_K_M.gguf"
)

// --- Helper Functions ---

func getWordlists() []string {
	files, _ := filepath.Glob(filepath.Join(fuzzerDir, "wordlists", "*.txt"))
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	if len(names) == 0 {
		names = append(names, "seclists_common.txt")
	}
	return names
}

func getLogFiles() []string {
	files, _ := filepath.Glob(filepath.Join(logDir, "*.log"))
	var names []string
	for _, f := range files {
		name := filepath.Base(f)
		if name != "dashboard.log" {
			names = append(names, name)
		}
	}
	return names
}

func getJobStatus() string {
	cmd := exec.Command("squeue", "--name=stealth_fuzz", "--format=%.10i %.8j %.8u %.2t %.10M %.6D %R")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "Slurm cluster not responding or squeue not found."
	}
	return string(out)
}

func getProgress(wordlistName string) (int, int) {
	if wordlistName == "" {
		wordlistName = "seclists_common.txt"
	}
	wordlistPath := filepath.Join(fuzzerDir, "wordlists", wordlistName)
	f, err := os.Open(wordlistPath)
	if err != nil {
		return 1, 0
	}
	scanner := bufio.NewScanner(f)
	total := 0
	for scanner.Scan() {
		total++
	}
	f.Close()

	files, _ := filepath.Glob(filepath.Join(logDir, "node*_*.log"))
	processed := 0
	for _, file := range files {
		f, _ := os.Open(file)
		s := bufio.NewScanner(f)
		for s.Scan() {
			processed++
		}
		f.Close()
	}
	
	return total, processed
}

func splitClean(s string) []string {
	if s == "" { return nil }
	parts := strings.Split(s, ",")
	var cleaned []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return cleaned
}

func matchFilters(line string, filters, excludes []string, statusRe, sizeRe *regexp.Regexp) bool {
	if len(filters) == 0 { return false }
	
	// Only show actual discoveries in the Active Findings view
	if !strings.Contains(line, "[+] Found") {
		return false
	}

	statusMatches := statusRe.FindStringSubmatch(line)
	if len(statusMatches) < 2 { return false }
	
	status := statusMatches[1]
	statusOk := false
	for _, f := range filters {
		if status == f { statusOk = true; break }
	}
	if !statusOk { return false }
	
	sizeMatches := sizeRe.FindStringSubmatch(line)
	if len(sizeMatches) >= 2 {
		size := sizeMatches[1]
		for _, e := range excludes {
			if size == e { return false }
		}
	}
	
	return true
}

func gatherFindingsStr(filters, excludeSizes string) string {
	statusRegex := regexp.MustCompile(`Status: (\d+)`)
	sizeRegex := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	
	filterList := splitClean(filters)
	excludeList := splitClean(excludeSizes)
	
	files, _ := filepath.Glob(filepath.Join(logDir, "*.log"))
	var sb strings.Builder
	count := 0
	
	for _, file := range files {
		if filepath.Base(file) == "dashboard.log" { continue }
		f, _ := os.Open(file)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if matchFilters(line, filterList, excludeList, statusRegex, sizeRegex) {
				sb.WriteString(line + "\n")
				count++
				if count > 100 { break } 
			}
		}
		f.Close()
		if count > 100 { break }
	}
	return sb.String()
}

// --- API Endpoints ---

func apiStatus(w http.ResponseWriter, r *http.Request) {
	wordlist := r.URL.Query().Get("wordlist")
	total, processed := getProgress(wordlist)
	
	data := map[string]interface{}{
		"wordlists": getWordlists(),
		"logFiles":  getLogFiles(),
		"jobStatus": getJobStatus(),
		"progress": map[string]int{
			"total":     total,
			"processed": processed,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func apiFindings(w http.ResponseWriter, r *http.Request) {
	filters := r.URL.Query().Get("filters")
	excludeSizes := r.URL.Query().Get("exclude_sizes")
	
	statusRegex := regexp.MustCompile(`Status: (\d+)`)
	sizeRegex := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	urlRegex := regexp.MustCompile(`(https?://[^\s]+)`)
	
	filterList := splitClean(filters)
	excludeList := splitClean(excludeSizes)
	
	files, _ := filepath.Glob(filepath.Join(logDir, "*.log"))
	w.Header().Set("Content-Type", "text/html")
	
	count := 0
	for _, file := range files {
		if filepath.Base(file) == "dashboard.log" { continue }
		f, _ := os.Open(file)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if matchFilters(line, filterList, excludeList, statusRegex, sizeRegex) {
				urlMatch := urlRegex.FindString(line)
				statusMatch := statusRegex.FindStringSubmatch(line)
				sizeMatch := sizeRegex.FindStringSubmatch(line)
				
				status := ""
				if len(statusMatch) > 1 { status = statusMatch[1] }
				size := ""
				if len(sizeMatch) > 1 { size = sizeMatch[1] }

				if urlMatch != "" {
					fmt.Fprintf(w, "[%s] <a href='%s' target='_blank' class='finding-link'>%s</a> (Size: %s)\n", status, urlMatch, urlMatch, size)
				} else {
					fmt.Fprintf(w, "%s\n", line)
				}
				count++
			}
		}
		f.Close()
	}
	if count == 0 {
		fmt.Fprintf(w, "<i style='color:var(--text-muted);'>No findings match the current filters.</i>")
	}
}

func getRawLogs(fileName, filterText string) string {
	var files []string
	if fileName == "all" || fileName == "" {
		files, _ = filepath.Glob(filepath.Join(logDir, "*.log"))
	} else {
		files = []string{filepath.Join(logDir, fileName)}
	}

	var matchedLines []string
	filterText = strings.ToLower(filterText)

	for _, file := range files {
		if filepath.Base(file) == "dashboard.log" { continue }
		f, err := os.Open(file)
		if err != nil { continue }
		
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if filterText == "" || strings.Contains(strings.ToLower(line), filterText) {
				matchedLines = append(matchedLines, fmt.Sprintf("[%s] %s", filepath.Base(file), line))
			}
		}
		f.Close()
	}

	if len(matchedLines) > 300 {
		matchedLines = matchedLines[len(matchedLines)-300:]
	}
	
	return strings.Join(matchedLines, "\n")
}

func apiRawLogs(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("raw_file")
	filterText := strings.ToLower(r.URL.Query().Get("raw_filter"))
	
	rawStr := getRawLogs(fileName, filterText)
	w.Header().Set("Content-Type", "text/plain")
	
	if rawStr == "" {
		fmt.Fprintf(w, "No raw logs found.")
	} else {
		fmt.Fprintf(w, rawStr)
	}
}

func apiAction(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	action := r.FormValue("action")
	msg := ""
	
	switch action {
	case "launch":
		targetUrl := r.FormValue("url")
		filters := r.FormValue("filters")
		wordlist := r.FormValue("wordlist")
		depth := r.FormValue("depth")
		if depth == "" { depth = "2" }
		modes := r.FormValue("modes")
		
		cmd := exec.Command(runScript, targetUrl, filters, wordlist, depth, modes)
		if err := cmd.Start(); err != nil {
			msg = fmt.Sprintf("Error launching: %v", err)
		} else {
			msg = "Campaign launched successfully!"
		}
	case "stop":
		cmd := exec.Command("scancel", "--jobname=stealth_fuzz")
		if err := cmd.Run(); err != nil {
			msg = fmt.Sprintf("Error stopping job: %v", err)
		} else {
			msg = "Stop command issued to cluster."
		}
	case "clear":
		files, _ := filepath.Glob(filepath.Join(logDir, "*.log"))
		for _, f := range files {
			if filepath.Base(f) != "dashboard.log" {
				os.Remove(f)
			}
		}
		msg = "Fuzzing logs cleared."
	default:
		msg = "Unknown action."
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

func apiAnalyze(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	promptType := r.FormValue("prompt_type")
	sourceType := r.FormValue("source_type")
	
	var dataToAnalyze string
	
	if sourceType == "findings" {
		filters := r.FormValue("filters")
		excludeSizes := r.FormValue("exclude_sizes")
		dataToAnalyze = gatherFindingsStr(filters, excludeSizes)
	} else {
		fileName := r.FormValue("raw_file")
		filterText := r.FormValue("raw_filter")
		rawStr := getRawLogs(fileName, filterText)
		lines := strings.Split(rawStr, "\n")
		if len(lines) > 200 {
			lines = lines[len(lines)-200:]
		}
		dataToAnalyze = strings.Join(lines, "\n")
	}
	
	if dataToAnalyze == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"report": "No data available to analyze based on current filters."})
		return
	}

	systemPrompt := ""
	switch promptType {
	case "audit":
		systemPrompt = "Analyze the following web fuzzing results. Identify any potentially sensitive exposed files, directories, or critical security vulnerabilities based on the paths and status codes. Keep the analysis concise and professional."
	case "summary":
		systemPrompt = "Provide a high-level summary of the most frequent errors, unusual status codes, and failed access attempts found in these logs."
	case "extract":
		systemPrompt = "Extract any unique IPs, email addresses, suspected credentials, or API keys visible in these logs. Present them as a simple list."
	default:
		systemPrompt = "Analyze the following logs for security relevance."
	}
	
	fullPrompt := fmt.Sprintf("%s\n\n%s", systemPrompt, dataToAnalyze)
	
	cmd := exec.Command("mpirun", 
		"--mca", "btl_tcp_if_include", "192.168.1.0/24",
		"--mca", "btl", "tcp,self",
		"--host", "node01:12,node02:4,node03:16,node04:16,node06:12",
		"--oversubscribe",
		llmBinary,
		"-m", llmModel,
		"-p", fullPrompt,
		"-n", "256",
	)
	
	out, err := cmd.CombinedOutput()
	report := ""
	if err != nil {
		report = fmt.Sprintf("AI Analysis failed: %v\nOutput: %s", err, string(out))
	} else {
		res := string(out)
		if strings.Contains(res, fullPrompt) {
			parts := strings.Split(res, fullPrompt)
			report = strings.TrimSpace(parts[len(parts)-1])
		} else {
			report = res
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"report": report})
}

// GET / (Main UI)
func serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	
	wordlists := getWordlists()
	selectedWordlist := "seclists_common.txt"
	
	depth := strings.TrimSpace(r.FormValue("depth"))
	if depth == "" { depth = "2" }

	total, processed := getProgress(selectedWordlist)
	p := 0
	if total > 0 { p = (processed * 100) / total }
	barWidth := p
	if barWidth > 100 { barWidth = 100 }
	
	progressText := fmt.Sprintf("%d%% Complete (%d/%d)", p, processed, total)
	if p >= 100 {
		progressText = fmt.Sprintf("Crawling Phase (%d requests)", processed)
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
	<title>HCP Fuzzer Command Center</title>
	<style>
		:root {
			--primary: #00ffff;
			--success: #39ff14;
			--danger: #ff003c;
			--warning: #ffb000;
			--purple: #bf00ff;
			--gray: #4b5563;
			
			--bg: #05080f;
			--card-bg: #0a0e17;
			--dark: #e2e8f0;
			--text-muted: #94a3b8;
			--border: #1e293b;
			--input-border: #334155;
			--input-bg: #0f172a;
			
			--term-bg: #000000;
			--term-text: #39ff14;
			--pre-bg: #020617;
			--pre-border: #1e293b;
		}

		body { 
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
			background-color: var(--bg); 
			color: var(--dark); 
			margin: 0; 
			padding: 10px; 
			height: 100vh; 
			box-sizing: border-box; 
			overflow: hidden;
		}
		
		.container { 
			display: grid; 
			grid-template-rows: auto 1fr; 
			height: 100%%; 
			gap: 10px;
		}
		
		.header { 
			display: flex; 
			justify-content: space-between; 
			align-items: center; 
			border-bottom: 1px solid var(--primary); 
			padding-bottom: 5px;
		}
		
		h1 { 
			color: var(--primary); 
			font-size: 1.5em; 
			margin: 0; 
			text-transform: uppercase; 
			letter-spacing: 2px;
		}
		
		.dashboard-grid { 
			display: grid; 
			grid-template-columns: 350px 1fr; 
			gap: 10px; 
			height: 100%%; 
			overflow: hidden;
		}
		
		.controls-col {
			display: flex;
			flex-direction: column;
			gap: 10px;
			height: 100%%;
			overflow-y: auto;
			padding-right: 5px;
		}
		
		.viewers-col {
			display: flex;
			flex-direction: column;
			gap: 10px;
			height: 100%%;
			overflow: hidden;
		}
		
		.card { 
			background: var(--card-bg); 
			border: 1px solid var(--border); 
			padding: 15px; 
			border-radius: 0px; 
			box-shadow: inset 0 0 10px rgba(0,0,0,0.5); 
		}
		
		.card h3 { 
			margin-top: 0; 
			color: var(--primary); 
			border-bottom: 1px dashed var(--border); 
			padding-bottom: 5px; 
			font-size: 0.9em; 
			text-transform: uppercase; 
			display: flex; 
			align-items: center; 
			justify-content: space-between;
		}
		
		label { display: block; margin: 8px 0 4px; font-weight: bold; font-size: 0.75em; color: var(--text-muted); text-transform: uppercase;}
		input[type="text"], input[type="number"], select { 
			width: 100%%; padding: 8px; border: 1px solid var(--input-border); background-color: var(--input-bg); 
			color: var(--dark); border-radius: 0; box-sizing: border-box; font-size: 13px; font-family: 'Consolas', monospace;
		}
		input[type="text"]:focus, input[type="number"]:focus, select:focus { border-color: var(--primary); outline: none; }
		
		.btn-group { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 15px; }
		.btn { 
			padding: 8px 12px; border: 1px solid transparent; border-radius: 0; cursor: pointer; font-weight: bold; 
			color: #000; font-size: 12px; text-transform: uppercase; flex: 1; text-align: center; 
			display: inline-flex; align-items: center; justify-content: center; gap: 5px;
		}
		.btn:hover:not(:disabled) { filter: brightness(120%%); }
		.btn:active:not(:disabled) { transform: scale(0.98); }
		.btn:disabled { opacity: 0.5; cursor: not-allowed; }
		
		.btn-launch { background-color: var(--success); border-color: var(--success); }
		.btn-stop { background-color: var(--danger); color: white; border-color: var(--danger); }
		.btn-clear { background-color: transparent; color: var(--text-muted); border-color: var(--border); }
		.btn-clear:hover:not(:disabled) { background-color: var(--border); color: white; }
		.btn-analyze { background-color: var(--purple); color: white; flex-basis: 100%%; border-color: var(--purple); }
		.btn-analyze-raw { background-color: transparent; color: var(--purple); border-color: var(--purple); }
		.btn-analyze-raw:hover:not(:disabled) { background-color: rgba(191, 0, 255, 0.2); }
		
		pre { background: var(--pre-bg); color: var(--dark); padding: 10px; border-radius: 0; overflow-x: auto; font-size: 12px; line-height: 1.4; margin: 0; border: 1px solid var(--pre-border); font-family: 'Consolas', 'Fira Code', monospace;}
		
		.findings-box { flex: 1; overflow-y: auto; }
		.raw-box { flex: 1; overflow-y: auto; color: var(--term-text); background-color: var(--term-bg); border-color: #333;}
		
		.live-terminal { background-color: var(--term-bg); color: var(--term-text); font-family: 'Consolas', monospace; padding: 10px; height: 150px; overflow-y: auto; font-size: 11px; margin-bottom: 5px; border: 1px solid #333; }
		.live-terminal .log-line { margin: 0; padding: 1px 0; border-bottom: 1px dotted #111; word-wrap: break-word; }
		
		.progress-container { width: 100%%; background-color: var(--input-bg); border-radius: 0; height: 16px; margin: 5px 0; overflow: hidden; position: relative; border: 1px solid var(--border); }
		.progress-bar { height: 100%%; background: var(--primary); transition: width 0.5s ease; }
		.progress-text { position: absolute; width: 100%%; text-align: center; top: 1px; font-weight: bold; color: #fff; font-size: 10px; text-shadow: 0 1px 1px rgba(0,0,0,0.8); }

		#notificationArea { position: fixed; top: 10px; right: 10px; z-index: 1000; }
		.toast { padding: 10px 20px; margin-bottom: 5px; border-radius: 0; color: #000; font-weight: bold; border: 1px solid #000; animation: slideIn 0.2s ease-out forwards; font-size: 12px; text-transform: uppercase;}
		.toast.success { background-color: var(--success); }
		.toast.error { background-color: var(--danger); color: white; }
		@keyframes slideIn { from { transform: translateX(100%%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

		.finding-link { color: var(--primary); text-decoration: none; }
		.finding-link:hover { background-color: var(--primary); color: #000; }
		
		.ai-report { background: rgba(191, 0, 255, 0.05); border-left: 3px solid var(--purple); padding: 10px; font-style: italic; white-space: pre-wrap; display: none; margin-bottom: 10px;}
		
		/* Loading Spinner */
		.spinner { border: 2px solid rgba(0,0,0,0.2); border-radius: 50%%; border-top: 2px solid #000; width: 12px; height: 12px; animation: spin 1s linear infinite; display: none; }
		.btn-stop .spinner, .btn-analyze .spinner { border-color: rgba(255,255,255,0.2); border-top-color: #fff; }
		.btn-clear .spinner { border-color: rgba(255,255,255,0.2); border-top-color: var(--text-muted); }
		.btn-analyze-raw .spinner { border-color: rgba(191,0,255,0.2); border-top-color: var(--purple); }
		.ai-report .spinner { border-color: rgba(191, 0, 255, 0.2); border-top-color: var(--purple); width: 16px; height: 16px; margin-right: 8px;}
		@keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }

		/* Status Indicator */
		.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%%; margin-right: 6px; background-color: var(--gray); }
		.status-dot.live { background-color: var(--success); box-shadow: 0 0 6px var(--success); }
		.status-dot.error { background-color: var(--danger); box-shadow: 0 0 6px var(--danger); }

		.terminal-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 5px;}
		.terminal-controls { display: flex; align-items: center; gap: 10px; font-size: 11px; text-transform: uppercase;}
		.terminal-controls label { margin: 0; display: flex; align-items: center; gap: 4px; cursor: pointer; }
		
		.checkbox-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 5px; margin-bottom: 10px; }
		.checkbox-label { 
			display: flex; align-items: center; gap: 5px; cursor: pointer; font-size: 11px; 
			background: var(--input-bg); padding: 5px; border: 1px solid var(--border); transition: 0.2s;
			color: var(--text-muted);
		}
		.checkbox-label:hover { border-color: var(--primary); }
		.checkbox-label input:checked + span { color: var(--primary); font-weight: bold; }
	</style>
</head>
<body>
	<div id="notificationArea"></div>

	<div class="container">
		<div class="header">
			<h1><span style="color:var(--text-muted)">HCP</span> Command Center</h1>
		</div>

		<div class="dashboard-grid">
			<!-- LEFT COLUMN: Controls -->
			<div class="controls-col">
				<div class="card">
					<h3>Fuzzing Campaign</h3>
					<form id="campaignForm">
						<label>Target URL:</label>
						<input type="text" id="url" name="url" value="%s" required placeholder="https://example.com">
						
						<label>Status Search (e.g., 200, 403):</label>
						<input type="text" id="filters" name="filters" value="%s" pattern="^\d*(,\d+)*$">
						
						<label>Exclude Sizes (e.g., 474):</label>
						<input type="text" id="exclude_sizes" name="exclude_sizes" value="%s" placeholder="Optional">

						<label>Wordlist:</label>
						<select id="wordlist" name="wordlist">
							%s
						</select>
						
						<div class="btn-group">
							<button type="button" class="btn btn-launch" id="btnLaunch" onclick="doAction('launch', this)">
								<span class="spinner"></span> Launch
							</button>
							<button type="button" class="btn btn-stop" id="btnStop" onclick="doAction('stop', this)">
								<span class="spinner"></span> Stop
							</button>
							<button type="button" class="btn btn-clear" id="btnClear" onclick="doAction('clear', this)">
								<span class="spinner"></span> Clear Logs
							</button>
						</div>
					</form>
				</div>

				<div class="card">
					<h3>Advanced Fuzzing Modes</h3>
					
					<div class="checkbox-grid">
						<label class="checkbox-label"><input type="checkbox" id="mode_subdomain" value="subdomain"><span>Subdomain</span></label>
						<label class="checkbox-label"><input type="checkbox" id="mode_api" value="api"><span>API</span></label>
						<label class="checkbox-label"><input type="checkbox" id="mode_parameter" value="parameter"><span>Parameter</span></label>
						<label class="checkbox-label"><input type="checkbox" id="mode_method" value="method"><span>Method</span></label>
						<label class="checkbox-label" style="grid-column: span 2;"><input type="checkbox" id="mode_header" value="header"><span>Header Injection</span></label>
					</div>

					<label>Recursion Depth:</label>
					<input type="number" id="depth" name="depth" value="%s" min="0" max="5">
				</div>
				
				<div class="card">
					<div class="terminal-header">
						<h3 style="margin:0; border:none; padding:0;">
							<span id="sseStatusDot" class="status-dot"></span> Live Terminal
						</h3>
						<div class="terminal-controls">
							<label><input type="checkbox" id="autoScroll" checked> Scroll</label>
							<a href="#" onclick="document.getElementById('liveTerminal').innerHTML=''; return false;" style="color:var(--primary); text-decoration:none;">Clear</a>
						</div>
					</div>
					<pre id="liveTerminal" class="live-terminal"></pre>
					<div class="progress-container">
						<div id="progressBar" class="progress-bar" style="width: %d%%;"></div>
						<div id="progressText" class="progress-text">%s</div>
					</div>
					<pre id="jobStatus" style="font-size: 10px; padding: 5px; border-color: var(--border); margin-top: 5px;">Loading status...</pre>
				</div>
				
				<div class="card">
					<h3>AI Analysis</h3>
					<select id="prompt_type" style="margin-bottom: 5px;">
						<option value="audit">Security Audit (Vulns)</option>
						<option value="summary">Error Summary</option>
						<option value="extract">Extract IPs/Creds</option>
					</select>
					
					<div class="btn-group">
						<button type="button" class="btn btn-analyze" onclick="runAnalysis('findings', this)">
							<span class="spinner"></span> Analyze Findings
						</button>
						<button type="button" class="btn btn-analyze btn-analyze-raw" onclick="runAnalysis('raw', this)">
							<span class="spinner"></span> Analyze Raw Logs
						</button>
					</div>
				</div>
			</div>

			<!-- RIGHT COLUMN: Viewers -->
			<div class="viewers-col">
				
				<div id="aiReportBox" class="card ai-report">
					<div style="display:flex; align-items:center; margin-bottom: 5px;">
						<div id="aiSpinner" class="spinner" style="display:block;"></div>
						<span id="aiReportStatus" style="font-weight:bold; color: var(--purple); font-size:11px; text-transform:uppercase;">AI Report</span>
					</div>
					<div id="aiReportContent" style="color: var(--dark); font-style: normal; line-height: 1.4; font-family: 'Consolas', monospace; font-size: 12px;"></div>
				</div>

				<div class="card" style="flex: 1; display: flex; flex-direction: column;">
					<h3>Active Findings</h3>
					<pre id="findingsBox" class="findings-box">Loading findings...</pre>
				</div>

				<div class="card" style="flex: 1; display: flex; flex-direction: column;">
					<h3>Raw Log Explorer</h3>
					<div style="display: flex; gap: 5px; margin-bottom: 5px;">
						<div style="flex: 1;">
							<select id="raw_file" style="margin:0;"><option value="all">All Node Logs</option></select>
						</div>
						<div style="flex: 2;">
							<input type="text" id="raw_filter" placeholder="GREP SEARCH (e.g. ERROR, 404)" style="margin:0;">
						</div>
					</div>
					<pre id="rawLogsBox" class="raw-box">Loading logs...</pre>
				</div>
			</div>
		</div>
	</div>

	<script>
		function showToast(message, isError = false) {
			const container = document.getElementById('notificationArea');
			const toast = document.createElement('div');
			toast.className = 'toast ' + (isError ? 'error' : 'success');
			toast.textContent = message;
			container.appendChild(toast);
			setTimeout(() => { toast.remove(); }, 4000);
		}

		function setButtonLoading(btn, isLoading) {
			const spinner = btn.querySelector('.spinner');
			if (isLoading) {
				btn.disabled = true;
				if(spinner) spinner.style.display = 'inline-block';
			} else {
				btn.disabled = false;
				if(spinner) spinner.style.display = 'none';
			}
		}

		async function doAction(actionName, btn) {
			const formData = new URLSearchParams();
			formData.append('action', actionName);
			formData.append('url', document.getElementById('url').value);
			formData.append('filters', document.getElementById('filters').value);
			formData.append('wordlist', document.getElementById('wordlist').value);
			formData.append('depth', document.getElementById('depth').value);

			let activeModes = [];
			['subdomain', 'api', 'parameter', 'method', 'header'].forEach(m => {
				if(document.getElementById('mode_' + m) && document.getElementById('mode_' + m).checked) {
					activeModes.push(m);
				}
			});
			formData.append('modes', activeModes.join(','));

			if (actionName === 'clear') {
				document.getElementById('liveTerminal').innerHTML = '';
			}

			setButtonLoading(btn, true);

			try {
				const response = await fetch('/api/action', {
					method: 'POST',
					body: formData
				});
				const data = await response.json();
				showToast(data.message, data.message.toLowerCase().includes("error"));
				updateDashboard();
			} catch (e) {
				showToast("Failed to connect to server.", true);
			} finally {
				setButtonLoading(btn, false);
			}
		}

		async function runAnalysis(sourceType, btn) {
			const reportBox = document.getElementById('aiReportBox');
			const content = document.getElementById('aiReportContent');
			const spinner = document.getElementById('aiSpinner');
			const status = document.getElementById('aiReportStatus');
			
			reportBox.style.display = 'block';
			content.innerText = "";
			spinner.style.display = 'inline-block';
			status.innerText = " AI IS ANALYZING...";
			
			setButtonLoading(btn, true);

			const formData = new URLSearchParams();
			formData.append('prompt_type', document.getElementById('prompt_type').value);
			formData.append('source_type', sourceType);
			
			if (sourceType === 'findings') {
				formData.append('filters', document.getElementById('filters').value);
				formData.append('exclude_sizes', document.getElementById('exclude_sizes').value);
			} else {
				formData.append('raw_file', document.getElementById('raw_file').value);
				formData.append('raw_filter', document.getElementById('raw_filter').value);
			}

			try {
				const response = await fetch('/api/analyze', {
					method: 'POST',
					body: formData
				});
				const data = await response.json();
				spinner.style.display = 'none';
				status.innerText = "ANALYSIS COMPLETE:";
				content.innerText = data.report;
			} catch (e) {
				spinner.style.display = 'none';
				status.innerText = "ANALYSIS FAILED";
				content.innerText = e.message;
			} finally {
				setButtonLoading(btn, false);
			}
		}

		let lastFilterState = "";

		function updateSelectOptions(selectId, newOptions, keepSelected = true) {
			const select = document.getElementById(selectId);
			const currentVal = select.value;
			if (!newOptions || newOptions.length === 0) return; 
			
			let html = selectId === 'raw_file' ? '<option value="all">All Node Logs</option>' : '';
			newOptions.forEach(opt => {
				html += '<option value="' + opt + '">' + opt + '</option>';
			});
			select.innerHTML = html;
			
			if (keepSelected && currentVal) {
				const hasOption = Array.from(select.options).some(opt => opt.value === currentVal);
				if (hasOption) select.value = currentVal;
			}
		}

		function linkify(text) {
			const urlRegex = /(https?:\/\/[^\s\)]+)/g;
			return text.replace(urlRegex, function(url) {
				return '<a href="' + url + '" target="_blank" class="finding-link">' + url + '</a>';
			});
		}

		async function updateDashboard() {
			const filters = document.getElementById('filters').value;
			const exclude = document.getElementById('exclude_sizes').value;
			const wordlist = document.getElementById('wordlist').value;
			const depth = document.getElementById('depth').value;
			const rawFile = document.getElementById('raw_file').value;
			const rawFilter = document.getElementById('raw_filter').value;
			
			const currentFilterState = filters + "|" + exclude + "|" + wordlist + "|" + rawFile + "|" + rawFilter + "|" + depth;
			const cacheBuster = "&_t=" + Date.now();

			try {
				// 1. Fetch Status JSON
				const statusRes = await fetch('/api/status?wordlist=' + encodeURIComponent(wordlist) + cacheBuster);
				if (statusRes.ok) {
					const statusData = await statusRes.json();
					document.getElementById('jobStatus').innerText = statusData.jobStatus;
					updateSelectOptions('wordlist', statusData.wordlists);
					updateSelectOptions('raw_file', statusData.logFiles);

					// Update Progress Bar
					const total = statusData.progress.total;
					const processed = statusData.progress.processed;
					let p = 0;
					if (total > 0) {
						p = Math.floor((processed * 100) / total);
					}
					
					let barWidth = p;
					let text = p + '% Complete (' + processed + '/' + total + ')';
					
					if (p >= 100) {
						barWidth = 100;
						text = 'Crawling Phase (' + processed + ' requests)';
					}
					
					document.getElementById('progressBar').style.width = barWidth + '%%';
					document.getElementById('progressText').innerText = text;

					document.getElementById('sseStatusDot').className = 'status-dot live';

					if (currentFilterState !== lastFilterState) {
						lastFilterState = currentFilterState;

						// 2. Fetch Findings
						const findRes = await fetch('/api/findings?filters=' + encodeURIComponent(filters) + '&exclude_sizes=' + encodeURIComponent(exclude) + cacheBuster);
						if (findRes.ok) {
							document.getElementById('findingsBox').innerHTML = await findRes.text();
						}

						// 3. Fetch Raw Logs
						const rawRes = await fetch('/api/raw_logs?raw_file=' + encodeURIComponent(rawFile) + '&raw_filter=' + encodeURIComponent(rawFilter) + cacheBuster);
						if (rawRes.ok) {
							const rawText = await rawRes.text();
							document.getElementById('rawLogsBox').innerHTML = linkify(rawText);
						}
					}

					// 4. Fetch Terminal Logs (Live Polling instead of SSE)
					const termRes = await fetch('/api/raw_logs?raw_file=all&raw_filter=' + cacheBuster);
					if (termRes.ok) {
						const termText = await termRes.text();
						const terminal = document.getElementById('liveTerminal');
						const autoScroll = document.getElementById('autoScroll');
						
						// Check if currently scrolled to bottom
						const isAtBottom = terminal.scrollHeight - terminal.scrollTop <= terminal.clientHeight + 10;
						
						terminal.innerHTML = linkify(termText);
						
						if (autoScroll.checked && isAtBottom) {
							terminal.scrollTop = terminal.scrollHeight;
						}
					}
				}
			} catch (error) {
				console.error("Dashboard update failed", error);
				document.getElementById('sseStatusDot').className = 'status-dot error';
			}
		}

		// Initial load then start polling
		updateDashboard();
		setInterval(updateDashboard, 3000); // Poll every 3 seconds for smooth terminal updates

	</script>
</body>
</html>`, 
		r.FormValue("url"), r.FormValue("filters"), r.FormValue("exclude_sizes"), 
		getWordlistOptionsHtml(wordlists, selectedWordlist),
		depth, barWidth, progressText)
}

func getWordlistOptionsHtml(lists []string, selected string) string {
	var html strings.Builder
	for _, l := range lists {
		sel := ""
		if l == selected { sel = "selected" }
		html.WriteString(fmt.Sprintf("<option value='%s' %s>%s</option>", l, sel, l))
	}
	return html.String()
}

func main() {
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/api/status", apiStatus)
	http.HandleFunc("/api/findings", apiFindings)
	http.HandleFunc("/api/raw_logs", apiRawLogs)
	http.HandleFunc("/api/action", apiAction)
	http.HandleFunc("/api/analyze", apiAnalyze)
	
	port := "0.0.0.0:8000"
	log.Printf("AJAX Control Center live on http://%s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}