package web

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dogadmin/LinIR/internal/ai"
	"github.com/dogadmin/LinIR/internal/app"
	"github.com/dogadmin/LinIR/internal/collector"
	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/internal/output"
	"github.com/dogadmin/LinIR/internal/preflight"
	"github.com/dogadmin/LinIR/internal/selfcheck"
	"github.com/dogadmin/LinIR/internal/watch"
	"github.com/dogadmin/LinIR/internal/yara"
)

const (
	maxRequestBody = 1 << 20 // 1 MB
	maxWatchEvents = 10000
)

//go:embed ui/*
var uiFS embed.FS

// Server 是 LinIR 的 Web GUI 服务器
type Server struct {
	cfg        *config.Config
	host       string
	port       int
	token      string // bearer token for API auth
	result     *model.CollectionResult
	analysis   *model.AnalysisResult
	mu         sync.Mutex
	collecting bool

	// watch 模式状态
	watchCancel    context.CancelFunc
	watching       bool
	watchEvents    []watch.EnrichedEvent
	watchScanCount   int
	watchLastConns   int
	watchLastErr     string
	watchLastMode    string
	watchLastHits    int
}

func NewServer(cfg *config.Config, host string, port int) *Server {
	return &Server{cfg: cfg, host: host, port: port, token: generateToken()}
}

func generateToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "linir-fallback-token"
	}
	return hex.EncodeToString(b)
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	uiContent, err := fs.Sub(uiFS, "ui")
	if err != nil {
		return fmt.Errorf("加载 UI 资源: %w", err)
	}

	// Static UI — index.html is served with token injected; other files served as-is
	staticFS := http.FileServer(http.FS(uiContent))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Inject token into index.html so the frontend can authenticate API calls
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			indexData, err := fs.ReadFile(uiContent, "index.html")
			if err != nil {
				http.Error(w, "内部错误", http.StatusInternalServerError)
				return
			}
			// Insert a script tag with the token before </head>
			tokenScript := fmt.Sprintf(`<script>window.__LINIR_TOKEN__="%s";</script></head>`, s.token)
			html := strings.Replace(string(indexData), "</head>", tokenScript, 1)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(html))
			return
		}
		staticFS.ServeHTTP(w, r)
	})

	// All API routes require bearer token
	api := func(handler http.HandlerFunc) http.HandlerFunc {
		return s.requireAuth(handler)
	}

	// collect API
	mux.HandleFunc("/api/collect", api(s.handleCollect))
	mux.HandleFunc("/api/result", api(s.handleResult))
	mux.HandleFunc("/api/status", api(s.handleStatus))

	// watch API
	mux.HandleFunc("/api/watch/start", api(s.handleWatchStart))
	mux.HandleFunc("/api/watch/stop", api(s.handleWatchStop))
	mux.HandleFunc("/api/watch/events", api(s.handleWatchEvents))
	mux.HandleFunc("/api/watch/stream", api(s.handleWatchStream))

	// export API
	mux.HandleFunc("/api/export/csv", api(s.handleExportCSV))

	// analysis API (three-state)
	mux.HandleFunc("/api/analysis", api(s.handleAnalysis))
	mux.HandleFunc("/api/analysis/result", api(s.handleAnalysisResult))
	mux.HandleFunc("/api/analysis/retained", api(s.handleAnalysisRetained))
	mux.HandleFunc("/api/analysis/triggerable", api(s.handleAnalysisTriggerable))
	mux.HandleFunc("/api/analysis/timeline", api(s.handleAnalysisTimeline))

	// AI 分析 API
	mux.HandleFunc("/api/ai/chat", api(s.handleAIChat))
	mux.HandleFunc("/api/ai/analyze", api(s.handleAIAnalyze))

	// YARA + 文件浏览 API
	mux.HandleFunc("/api/fs/browse", api(s.handleFsBrowse))
	mux.HandleFunc("/api/fs/cwd", api(s.handleCwd))
	mux.HandleFunc("/api/yara/scan", api(s.handleYaraScan))

	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %w", addr, err)
	}

	url := fmt.Sprintf("http://%s", addr)
	fmt.Printf("LinIR GUI 已启动: %s\n", url)
	fmt.Printf("API Token: %s\n", s.token)
	fmt.Println("在浏览器中打开上方地址，或按 Ctrl+C 退出")

	go openBrowser(url)

	return http.Serve(listener, mux)
}

// requireAuth validates the bearer token on API requests.
// Accepts token via Authorization header or ?token= query parameter.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		}
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) != 1 {
			http.Error(w, "未授权访问", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}


// ========== Collect API ==========

func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	if s.collecting {
		s.mu.Unlock()
		http.Error(w, "采集正在进行中", http.StatusConflict)
		return
	}
	s.collecting = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.collecting = false
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Timeout)*time.Second)
	defer cancel()

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	yaraRules := ""
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			YaraRules string `json:"yara_rules"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		yaraRules = body.YaraRules
	}

	if yaraRules != "" {
		if !filepath.IsAbs(yaraRules) {
			http.Error(w, "YARA 规则路径必须是绝对路径", http.StatusBadRequest)
			return
		}
		if _, err := os.Stat(yaraRules); err != nil {
			http.Error(w, "YARA 规则路径不存在", http.StatusBadRequest)
			return
		}
	}

	guiCfg := *s.cfg
	guiCfg.OutputFormat = "json"
	guiCfg.Quiet = true
	if yaraRules != "" {
		guiCfg.YaraRules = yaraRules
	}

	application, err := app.New(&guiCfg)
	if err != nil {
		http.Error(w, "初始化采集器失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = application.RunFull(ctx)
	result := application.Result()

	s.mu.Lock()
	s.result = result
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	result := s.result
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if result == nil {
		w.Write([]byte("null"))
		return
	}
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	status := map[string]interface{}{
		"collecting":    s.collecting,
		"has_result":    s.result != nil,
		"has_analysis":  s.analysis != nil,
		"watching":      s.watching,
		"watch_events":  len(s.watchEvents),
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// ========== Watch API ==========

// handleWatchStart 启动 IOC 监控
func (s *Server) handleWatchStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}

	// 立即抢占 watching 标志，防止并发双启动
	s.mu.Lock()
	if s.watching {
		s.mu.Unlock()
		http.Error(w, "监控已在运行中", http.StatusConflict)
		return
	}
	s.watching = true // 先锁定，失败时回滚
	s.mu.Unlock()

	// 初始化失败时回滚 watching 状态
	rollback := func() {
		s.mu.Lock()
		s.watching = false
		s.mu.Unlock()
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var body struct {
		IOCs      string `json:"iocs"`
		Interval  int    `json:"interval"`
		YaraRules string `json:"yara_rules"`
		Interface string `json:"iface"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		rollback()
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.IOCs) == "" {
		rollback()
		http.Error(w, "IOC 列表不能为空", http.StatusBadRequest)
		return
	}

	tmpFile, err := os.CreateTemp("", "linir-iocs-*.txt")
	if err != nil {
		rollback()
		http.Error(w, "创建临时文件失败", http.StatusInternalServerError)
		return
	}
	tmpFile.WriteString(body.IOCs)
	tmpFile.Close()
	tmpName := tmpFile.Name()

	interval := 1
	if body.Interval > 0 {
		interval = body.Interval
	}

	collectors, err := collector.NewPlatformCollectors()
	if err != nil {
		os.Remove(tmpName)
		rollback()
		http.Error(w, "初始化采集器失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	iocStore, err := watch.LoadIOCFile(tmpName)
	if err != nil {
		os.Remove(tmpName)
		rollback()
		http.Error(w, "IOC 解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	sc, _ := selfcheck.Run(context.Background())
	pf, _ := preflight.Run(context.Background(), s.cfg)
	trigger := watch.NewTriggerPolicy(60*time.Second, 0, nil)
	enricher := watch.NewEnricher(collectors, body.YaraRules, pf, sc)

	ctx, cancel := context.WithCancel(context.Background())

	s.mu.Lock()
	s.watchCancel = cancel
	s.watchEvents = nil
	s.mu.Unlock()

	// 确定监控模式（在 goroutine 之前，供响应使用）
	monitorMode := "轮询"
	if watch.ConntrackAvailable() {
		monitorMode = "事件驱动"
	} else if watch.NfConntrackAvailable() {
		monitorMode = "nf_conntrack"
	}

	// 后台运行监控循环
	go func() {
		defer func() {
			s.mu.Lock()
			s.watching = false
			s.mu.Unlock()
			os.Remove(tmpName)
		}()

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		handleHit := func(hit watch.HitEvent) {
			decision := trigger.Evaluate(hit)
			if !decision.ShouldEnrich {
				return
			}
			cache := enricher.CollectCache(ctx)
			evt := enricher.Enrich(ctx, hit, cache)
			s.mu.Lock()
			// 如果有 PID，用完整5元组检查是否能替换之前的 PID=0 事件
			replaced := false
			if evt.Connection.PID > 0 {
				evtKey := watch.ConnKey(evt.Connection)
				for i := range s.watchEvents {
					if s.watchEvents[i].Connection.PID == 0 &&
						s.watchEvents[i].IOC.Value == evt.IOC.Value &&
						watch.ConnKey(s.watchEvents[i].Connection) == evtKey {
						s.watchEvents[i] = evt
						replaced = true
						break
					}
				}
			}
			if !replaced {
				if len(s.watchEvents) < maxWatchEvents {
					s.watchEvents = append(s.watchEvents, evt)
				}
			}
			s.mu.Unlock()
		}

		// pending: conntrack/BPF 事件 PID=0 暂存，等轮询补全
		var pendingHits []watch.HitEvent

		useNfConntrack := monitorMode == "nf_conntrack"
		var ctEvents <-chan watch.HitEvent
		var ctErrCh <-chan error

		if monitorMode == "事件驱动" {
			ctMonitor := watch.NewConntrackMonitor(iocStore, body.Interface, nil)
			errCh := make(chan error, 1)
			go func() {
				errCh <- ctMonitor.Run(ctx)
			}()
			ctEvents = ctMonitor.Events()
			ctErrCh = errCh
		}

		scanOnce := func() {
			var conns []model.ConnectionInfo
			var scanErr error

			if useNfConntrack {
				conns, scanErr = watch.CollectWithNfConntrack(ctx, collectors)
			} else {
				conns, scanErr = collectors.Network.CollectConnections(ctx)
			}

			pendingHits = watch.ResolvePendingHits(pendingHits, conns, handleHit, handleHit)

			hitCount := 0
			if len(conns) > 0 {
				hits := watch.MatchConnections(conns, iocStore)
				hitCount = len(hits)
				for _, hit := range hits {
					handleHit(hit)
				}
			}

			s.mu.Lock()
			s.watchScanCount++
			s.watchLastConns = len(conns)
			s.watchLastMode = monitorMode
			s.watchLastHits = hitCount
			if scanErr != nil {
				s.watchLastErr = scanErr.Error()
			} else {
				s.watchLastErr = ""
			}
			s.mu.Unlock()
		}

		scanOnce() // 首次轮询

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				scanOnce()
			case hit := <-ctEvents:
				if watch.ResolveHitPIDWithRetry(ctx, &hit, collectors) {
					handleHit(hit)
				} else {
					pendingHits = append(pendingHits, hit)
				}
			case err := <-ctErrCh:
				// conntrack/BPF 失败，记录错误并继续轮询
				if err != nil {
					s.mu.Lock()
					s.watchLastErr = "事件驱动失败: " + err.Error()
					s.mu.Unlock()
				}
				ctEvents = nil // 停止从 channel 读取
				ctErrCh = nil
			}
		}
	}()

	// 收集已加载的 IOC 列表（前 10 条，供前端诊断显示）
	var iocSamples []string
	for k := range iocStore.ListIPs() {
		if len(iocSamples) >= 10 {
			break
		}
		iocSamples = append(iocSamples, k)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "started",
		"ioc_count":   iocStore.Total(),
		"ioc_samples": iocSamples,
		"interval":    interval,
		"mode":        monitorMode,
	})
}

// handleWatchStop 停止 IOC 监控
func (s *Server) handleWatchStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	if !s.watching {
		s.mu.Unlock()
		http.Error(w, "监控未在运行", http.StatusConflict)
		return
	}
	if s.watchCancel != nil {
		s.watchCancel()
	}
	s.mu.Unlock()

	// 等一下让 goroutine 退出
	time.Sleep(100 * time.Millisecond)

	s.mu.Lock()
	count := len(s.watchEvents)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "stopped",
		"total_events": count,
	})
}

// handleWatchEvents 返回所有已收集的 watch 事件
func (s *Server) handleWatchEvents(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	events := make([]watch.EnrichedEvent, len(s.watchEvents))
	copy(events, s.watchEvents)
	watching := s.watching
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"watching": watching,
		"events":   events,
	})
}

// handleWatchStream SSE 事件流——浏览器实时接收新事件
func (s *Server) handleWatchStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "不支持 SSE", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	lastIdx := 0
	lastStatusKey := ""
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			newCount := len(s.watchEvents)
			var newEvents []watch.EnrichedEvent
			if newCount > lastIdx {
				newEvents = make([]watch.EnrichedEvent, newCount-lastIdx)
				copy(newEvents, s.watchEvents[lastIdx:newCount])
			}
			watching := s.watching
			scanCount := s.watchScanCount
			lastConns := s.watchLastConns
			lastErr := s.watchLastErr
			mode := s.watchLastMode
			lastHits := s.watchLastHits
			s.mu.Unlock()

			// 发送新事件
			for _, evt := range newEvents {
				data, _ := json.Marshal(evt)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
			lastIdx = newCount

			// 发送扫描状态（仅在状态变化时发送，避免刷屏）
			statusKey := fmt.Sprintf("%d:%d:%d:%d:%s", scanCount, lastConns, newCount, lastHits, lastErr)
			if statusKey != lastStatusKey {
				lastStatusKey = statusKey
				statusJSON, _ := json.Marshal(map[string]interface{}{
					"scans":      scanCount,
					"last_conns": lastConns,
					"last_err":   lastErr,
					"last_hits":  lastHits,
					"events":     newCount,
					"watching":   watching,
					"mode":       mode,
				})
				fmt.Fprintf(w, "event: status\ndata: %s\n\n", statusJSON)
				flusher.Flush()
			}

			if !watching && lastIdx >= newCount {
				fmt.Fprintf(w, "event: done\ndata: {\"total\": %d}\n\n", newCount)
				flusher.Flush()
				return
			}
		}
	}
}

// ========== Export API ==========

// handleExportCSV 将当前数据导出为 CSV（打包成 zip 下载）
func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	result := s.result
	analysis := s.analysis
	s.mu.Unlock()

	if result == nil && analysis == nil {
		http.Error(w, "无数据可导出，请先执行采集或分析", http.StatusBadRequest)
		return
	}

	// 写 CSV 到临时目录
	tmpDir, err := os.MkdirTemp("", "linir-csv-*")
	if err != nil {
		http.Error(w, "创建临时目录失败", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir)

	csvWriter := output.NewCSVWriter(tmpDir)

	if analysis != nil {
		if err := csvWriter.WriteAnalysis(analysis); err != nil {
			http.Error(w, "生成 CSV 失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else if result != nil {
		if err := csvWriter.Write(result); err != nil {
			http.Error(w, "生成 CSV 失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// 收集生成的 CSV 文件
	csvFiles, err := os.ReadDir(tmpDir)
	if err != nil || len(csvFiles) == 0 {
		http.Error(w, "未生成任何 CSV 文件", http.StatusInternalServerError)
		return
	}

	// 打包成 zip 返回
	hostname := "unknown"
	if result != nil && result.Host.Hostname != "" {
		hostname = result.Host.Hostname
	} else if analysis != nil && analysis.Host.Hostname != "" {
		hostname = analysis.Host.Hostname
	}

	// Build zip in memory to detect errors before sending headers
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, entry := range csvFiles {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".csv") {
			continue
		}
		filePath := filepath.Join(tmpDir, entry.Name())
		f, err := os.Open(filePath)
		if err != nil {
			continue
		}
		zf, err := zw.Create(entry.Name())
		if err != nil {
			f.Close()
			continue
		}
		io.Copy(zf, f)
		f.Close()
	}

	if err := zw.Close(); err != nil {
		http.Error(w, "生成 ZIP 失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	zipName := fmt.Sprintf("linir-csv-%s.zip", hostname)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", zipName))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	io.Copy(w, &buf)
}

// ========== Analysis API (三维状态) ==========

// handleAnalysis 执行三维状态分析（runtime + retained + triggerable + timeline）
func (s *Server) handleAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	if s.collecting {
		s.mu.Unlock()
		http.Error(w, "采集正在进行中", http.StatusConflict)
		return
	}
	s.collecting = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.collecting = false
		s.mu.Unlock()
	}()

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var body struct {
		WithRetained    bool   `json:"with_retained"`
		WithTriggerable bool   `json:"with_triggerable"`
		WithTimeline    bool   `json:"timeline"`
		RetainedWindow  string `json:"retained_window"`
		YaraRules       string `json:"yara_rules"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		json.NewDecoder(r.Body).Decode(&body)
	}

	// 默认全开
	if !body.WithRetained && !body.WithTriggerable && !body.WithTimeline {
		body.WithRetained = true
		body.WithTriggerable = true
		body.WithTimeline = true
	}
	if body.WithTimeline {
		body.WithRetained = true
		body.WithTriggerable = true
	}

	guiCfg := *s.cfg
	guiCfg.OutputFormat = "json"
	guiCfg.Quiet = true
	guiCfg.WithRetained = body.WithRetained
	guiCfg.WithTriggerable = body.WithTriggerable
	guiCfg.WithTimeline = body.WithTimeline
	if body.YaraRules != "" {
		guiCfg.YaraRules = body.YaraRules
	}
	if body.RetainedWindow != "" {
		if d, err := time.ParseDuration(body.RetainedWindow); err == nil {
			guiCfg.RetainedWindow = d
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Timeout)*time.Second)
	defer cancel()

	application, err := app.New(&guiCfg)
	if err != nil {
		http.Error(w, "初始化采集器失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := application.RunAnalysis(ctx); err != nil {
		http.Error(w, "分析失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	result := application.Result()

	s.mu.Lock()
	s.result = result
	s.analysis = result.Analysis
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if result.Analysis != nil {
		json.NewEncoder(w).Encode(result.Analysis)
	} else {
		json.NewEncoder(w).Encode(result)
	}
}

// handleAnalysisResult 返回缓存的完整分析结果
func (s *Server) handleAnalysisResult(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	analysis := s.analysis
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if analysis == nil {
		w.Write([]byte("null"))
		return
	}
	json.NewEncoder(w).Encode(analysis)
}

// handleAnalysisRetained 返回缓存的 retained 数据
func (s *Server) handleAnalysisRetained(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	analysis := s.analysis
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if analysis == nil || analysis.Retained == nil {
		w.Write([]byte("null"))
		return
	}
	json.NewEncoder(w).Encode(analysis.Retained)
}

// handleAnalysisTriggerable 返回缓存的 triggerable 数据
func (s *Server) handleAnalysisTriggerable(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	analysis := s.analysis
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if analysis == nil || analysis.Triggerable == nil {
		w.Write([]byte("null"))
		return
	}
	json.NewEncoder(w).Encode(analysis.Triggerable)
}

// handleAnalysisTimeline 返回缓存的 timeline 数据
func (s *Server) handleAnalysisTimeline(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	analysis := s.analysis
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if analysis == nil || len(analysis.Timeline) == 0 {
		w.Write([]byte("null"))
		return
	}
	json.NewEncoder(w).Encode(analysis.Timeline)
}

// ========== AI 分析 API ==========

func (s *Server) handleAIChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var body struct {
		APIKey   string       `json:"api_key"`
		Model    string       `json:"model"`
		Messages []ai.Message `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	if body.APIKey == "" {
		http.Error(w, "请输入 API Key", http.StatusBadRequest)
		return
	}
	if body.Model == "" {
		body.Model = "MiniMax-M2.5"
	}

	// Build system prompt with forensic context
	s.mu.Lock()
	result := s.result
	analysis := s.analysis
	s.mu.Unlock()

	systemPrompt := ai.BuildForensicContext(result, analysis)

	// Cap user history at 30 messages
	userMsgs := body.Messages
	if len(userMsgs) > 30 {
		userMsgs = userMsgs[len(userMsgs)-30:]
	}

	reply, err := ai.ChatCompletion(r.Context(), body.APIKey, body.Model, systemPrompt, userMsgs)
	if err != nil {
		http.Error(w, "AI 调用失败: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"reply": ai.StripThinking(reply),
	})
}

func (s *Server) handleAIAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var body struct {
		APIKey string `json:"api_key"`
		Model  string `json:"model"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	if body.APIKey == "" {
		http.Error(w, "请输入 API Key", http.StatusBadRequest)
		return
	}
	if body.Model == "" {
		body.Model = "MiniMax-M2.5"
	}

	s.mu.Lock()
	result := s.result
	analysis := s.analysis
	s.mu.Unlock()

	if result == nil && analysis == nil {
		http.Error(w, "请先执行采集或分析", http.StatusBadRequest)
		return
	}

	systemPrompt := ai.BuildForensicContext(result, analysis)
	messages := []ai.Message{
		{Role: "user", Content: "综合分析这台主机的安全状态。直接给结论：\n1. 是否被入侵（判定+依据）\n2. 关键发现（列出最重要的 3-5 条）\n3. 处置建议（具体操作步骤）\n4. 需要进一步排查的点"},
	}

	reply, err := ai.ChatCompletion(r.Context(), body.APIKey, body.Model, systemPrompt, messages)
	if err != nil {
		http.Error(w, "AI 调用失败: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"reply": ai.StripThinking(reply),
	})
}

// ========== YARA + 文件浏览 API ==========

// handleCwd 返回服务器当前工作目录
func (s *Server) handleCwd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "需要 GET", http.StatusMethodNotAllowed)
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "/"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"cwd": cwd})
}

// handleFsBrowse 返回目录列表，供前端文件浏览器使用
func (s *Server) handleFsBrowse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "需要 GET", http.StatusMethodNotAllowed)
		return
	}
	dir := r.URL.Query().Get("path")
	if dir == "" {
		dir = "/"
	}
	if !filepath.IsAbs(dir) {
		http.Error(w, "必须是绝对路径", http.StatusBadRequest)
		return
	}
	dir = filepath.Clean(dir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "无法读取目录", http.StatusBadRequest)
		return
	}

	type fsEntry struct {
		Name  string `json:"name"`
		IsDir bool   `json:"is_dir"`
		Size  int64  `json:"size"`
	}

	const maxEntries = 1000

	result := struct {
		Path      string    `json:"path"`
		Parent    string    `json:"parent"`
		Entries   []fsEntry `json:"entries"`
		Truncated bool      `json:"truncated,omitempty"`
	}{
		Path:    dir,
		Parent:  filepath.Dir(dir),
		Entries: []fsEntry{},
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		fe := fsEntry{Name: entry.Name(), IsDir: entry.IsDir()}
		if !entry.IsDir() {
			if info, err := entry.Info(); err == nil {
				fe.Size = info.Size()
			}
		}
		result.Entries = append(result.Entries, fe)
		if len(result.Entries) >= maxEntries {
			result.Truncated = true
			break
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(result)
}

// handleYaraScan 采集当前进程/网络/持久化信息，用 YARA 扫描关联文件
func (s *Server) handleYaraScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var body struct {
		RulesPath string `json:"rules_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}

	if body.RulesPath == "" {
		http.Error(w, "规则路径不能为空", http.StatusBadRequest)
		return
	}
	if !filepath.IsAbs(body.RulesPath) {
		http.Error(w, "规则路径必须是绝对路径", http.StatusBadRequest)
		return
	}

	if !yara.Available() {
		http.Error(w, "YARA 支持未编译", http.StatusBadRequest)
		return
	}

	scanner, err := yara.NewScanner(body.RulesPath)
	if err != nil {
		http.Error(w, "加载 YARA 规则失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	// 采集进程/网络/持久化，构建扫描目标
	collectors, err := collector.NewPlatformCollectors()
	if err != nil {
		http.Error(w, "初始化采集器失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	result := &model.CollectionResult{}
	if procs, err := collectors.Process.CollectProcesses(ctx); err == nil {
		result.Processes = procs
	}
	if conns, err := collectors.Network.CollectConnections(ctx); err == nil {
		result.Connections = conns
	}
	if items, err := collectors.Persistence.CollectPersistence(ctx); err == nil {
		result.Persistence = items
	}

	targets := yara.CollectHighRiskTargets(result)

	var hits []model.YaraHit
	for _, target := range targets {
		select {
		case <-ctx.Done():
			break
		default:
		}
		h, scanErr := scanner.ScanFile(ctx, target.Path)
		if scanErr != nil {
			continue
		}
		for i := range h {
			h[i].TargetType = target.TargetType
			h[i].LinkedPID = target.LinkedPID
		}
		hits = append(hits, h...)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rule_count":   scanner.RuleCount(),
		"target_count": len(targets),
		"hits":         hits,
		"hit_count":    len(hits),
	})
}

func openBrowser(url string) {
	time.Sleep(300 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return
	}
	if err := cmd.Start(); err != nil {
		log.Printf("无法自动打开浏览器: %v\n请手动打开 %s", err, url)
	}
}
