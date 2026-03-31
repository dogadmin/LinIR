package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dogadmin/LinIR/internal/app"
	"github.com/dogadmin/LinIR/internal/collector"
	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/internal/preflight"
	"github.com/dogadmin/LinIR/internal/selfcheck"
	"github.com/dogadmin/LinIR/internal/watch"
)

//go:embed ui/*
var uiFS embed.FS

// Server 是 LinIR 的 Web GUI 服务器
type Server struct {
	cfg        *config.Config
	port       int
	result     *model.CollectionResult
	mu         sync.Mutex
	collecting bool

	// watch 模式状态
	watchCancel context.CancelFunc
	watching    bool
	watchEvents []watch.EnrichedEvent
}

func NewServer(cfg *config.Config, port int) *Server {
	return &Server{cfg: cfg, port: port}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	uiContent, err := fs.Sub(uiFS, "ui")
	if err != nil {
		return fmt.Errorf("加载 UI 资源: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(uiContent)))

	// collect API
	mux.HandleFunc("/api/collect", s.handleCollect)
	mux.HandleFunc("/api/result", s.handleResult)
	mux.HandleFunc("/api/status", s.handleStatus)

	// watch API
	mux.HandleFunc("/api/watch/start", s.handleWatchStart)
	mux.HandleFunc("/api/watch/stop", s.handleWatchStop)
	mux.HandleFunc("/api/watch/events", s.handleWatchEvents)
	mux.HandleFunc("/api/watch/stream", s.handleWatchStream)

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %w", addr, err)
	}

	url := fmt.Sprintf("http://%s", addr)
	fmt.Printf("LinIR GUI 已启动: %s\n", url)
	fmt.Println("在浏览器中打开上方地址，或按 Ctrl+C 退出")

	go openBrowser(url)

	return http.Serve(listener, mux)
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

	yaraRules := ""
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			YaraRules string `json:"yara_rules"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		yaraRules = body.YaraRules
	}

	if yaraRules != "" {
		if !strings.HasPrefix(yaraRules, "/") {
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
		"collecting":   s.collecting,
		"has_result":   s.result != nil,
		"watching":     s.watching,
		"watch_events": len(s.watchEvents),
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

	s.mu.Lock()
	if s.watching {
		s.mu.Unlock()
		http.Error(w, "监控已在运行中", http.StatusConflict)
		return
	}
	s.mu.Unlock()

	var body struct {
		IOCs      string `json:"iocs"`       // IOC 列表，每行一个
		Interval  int    `json:"interval"`    // 秒
		YaraRules string `json:"yara_rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.IOCs) == "" {
		http.Error(w, "IOC 列表不能为空", http.StatusBadRequest)
		return
	}

	// 将 IOC 文本写入临时文件
	tmpFile, err := os.CreateTemp("", "linir-iocs-*.txt")
	if err != nil {
		http.Error(w, "创建临时文件失败", http.StatusInternalServerError)
		return
	}
	tmpFile.WriteString(body.IOCs)
	tmpFile.Close()

	interval := 3
	if body.Interval > 0 {
		interval = body.Interval
	}

	// 初始化 watch engine
	wcfg := watch.WatchConfig{
		IOCFile:      tmpFile.Name(),
		Interval:     time.Duration(interval) * time.Second,
		DedupeWindow: 60 * time.Second,
		TextOutput:   false,
		JSONOutput:   false,
		YaraRules:    body.YaraRules,
	}

	// 构建 enricher 的依赖
	collectors, err := collector.NewPlatformCollectors()
	if err != nil {
		os.Remove(tmpFile.Name())
		http.Error(w, "初始化采集器失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	iocStore, err := watch.LoadIOCFile(tmpFile.Name())
	if err != nil {
		os.Remove(tmpFile.Name())
		http.Error(w, "IOC 解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	sc, _ := selfcheck.Run(context.Background())
	pf, _ := preflight.Run(context.Background(), s.cfg)
	trigger := watch.NewTriggerPolicy(wcfg.DedupeWindow, 0, nil)
	enricher := watch.NewEnricher(collectors, wcfg.YaraRules, pf, sc)

	ctx, cancel := context.WithCancel(context.Background())

	s.mu.Lock()
	s.watching = true
	s.watchCancel = cancel
	s.watchEvents = nil
	s.mu.Unlock()

	// 后台运行监控循环
	go func() {
		defer func() {
			s.mu.Lock()
			s.watching = false
			s.mu.Unlock()
			os.Remove(tmpFile.Name())
		}()

		ticker := time.NewTicker(wcfg.Interval)
		defer ticker.Stop()

		scanOnce := func() {
			conns, _ := collectors.Network.CollectConnections(ctx)
			if len(conns) == 0 {
				return
			}
			hits := watch.MatchConnections(conns, iocStore)
			for _, hit := range hits {
				select {
				case <-ctx.Done():
					return
				default:
				}
				decision := trigger.Evaluate(hit)
				if !decision.ShouldEnrich {
					continue
				}
				evt := enricher.Enrich(ctx, hit)

				s.mu.Lock()
				s.watchEvents = append(s.watchEvents, evt)
				s.mu.Unlock()
			}
		}

		scanOnce() // 立即执行一次

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				scanOnce()
			}
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "started",
		"ioc_count": iocStore.Total(),
		"interval":  interval,
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
	for {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(1 * time.Second):
			s.mu.Lock()
			events := s.watchEvents
			watching := s.watching
			s.mu.Unlock()

			// 发送新事件
			for lastIdx < len(events) {
				data, _ := json.Marshal(events[lastIdx])
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
				lastIdx++
			}

			// 发送心跳（保持连接）
			if lastIdx == len(events) {
				fmt.Fprintf(w, ": heartbeat watching=%v events=%d\n\n", watching, len(events))
				flusher.Flush()
			}

			if !watching && lastIdx >= len(events) {
				// 监控结束且所有事件已发送
				fmt.Fprintf(w, "event: done\ndata: {\"total\": %d}\n\n", len(events))
				flusher.Flush()
				return
			}
		}
	}
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
