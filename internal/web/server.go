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
	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/model"
)

//go:embed ui/*
var uiFS embed.FS

// Server 是 LinIR 的 Web GUI 服务器
type Server struct {
	cfg    *config.Config
	port   int
	result *model.CollectionResult
	mu     sync.Mutex
	collecting bool
}

// NewServer 创建 GUI 服务器
func NewServer(cfg *config.Config, port int) *Server {
	return &Server{cfg: cfg, port: port}
}

// Start 启动 HTTP 服务器并自动打开浏览器
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// 静态资源（从 embed.FS 中提取 ui/ 子目录）
	uiContent, err := fs.Sub(uiFS, "ui")
	if err != nil {
		return fmt.Errorf("加载 UI 资源: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(uiContent)))

	// API 路由
	mux.HandleFunc("/api/collect", s.handleCollect)
	mux.HandleFunc("/api/result", s.handleResult)
	mux.HandleFunc("/api/status", s.handleStatus)

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %w", addr, err)
	}

	url := fmt.Sprintf("http://%s", addr)
	fmt.Printf("LinIR GUI 已启动: %s\n", url)
	fmt.Println("在浏览器中打开上方地址，或按 Ctrl+C 退出")

	// 自动打开浏览器
	go openBrowser(url)

	return http.Serve(listener, mux)
}

// handleCollect 执行采集并返回 JSON 结果
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

	// 执行采集
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Timeout)*time.Second)
	defer cancel()

	// 从请求中读取可选的 YARA 规则路径
	yaraRules := ""
	if r.Header.Get("Content-Type") == "application/json" {
		var body struct {
			YaraRules string `json:"yara_rules"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		yaraRules = body.YaraRules
	} else {
		yaraRules = r.FormValue("yara_rules")
	}

	// 验证 YARA 规则路径安全性
	if yaraRules != "" {
		// 必须是绝对路径，防止路径遍历
		if !strings.HasPrefix(yaraRules, "/") {
			http.Error(w, "YARA 规则路径必须是绝对路径", http.StatusBadRequest)
			return
		}
		// 检查路径是否存在
		if _, err := os.Stat(yaraRules); err != nil {
			http.Error(w, "YARA 规则路径不存在: "+yaraRules, http.StatusBadRequest)
			return
		}
	}

	// GUI 模式下不写文件输出，只返回 JSON
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

	// 运行采集（不写文件，只填充 result）
	_ = application.RunFull(ctx)
	result := application.Result()

	s.mu.Lock()
	s.result = result
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(result)
}

// handleResult 返回上次采集结果（如果有）
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

// handleStatus 返回当前状态
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	status := map[string]interface{}{
		"collecting": s.collecting,
		"has_result": s.result != nil,
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// openBrowser 尝试自动打开浏览器
func openBrowser(url string) {
	time.Sleep(300 * time.Millisecond) // 等服务器就绪
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
