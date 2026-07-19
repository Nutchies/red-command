package recorder

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/red-team/agent/config"
	"github.com/red-team/agent/db"
)

const (
	recordDir          = "recordings"
	uploadInterval     = 60 * time.Second
	maxSegmentDuration = 60
	frameRate          = 5
	videoQuality       = 23
	maxWidth           = 1280
	maxHeight          = 720
)

type Recorder struct {
	cfg      *config.Config
	db       *db.DB
	sessions map[string]*DesktopSession
	mu       sync.Mutex
}

type DesktopSession struct {
	SessionID  string
	StartTime  time.Time
	PID        int
	OutputPath string
	IsActive   bool
	cmd        *exec.Cmd
}

func New(cfg *config.Config, database *db.DB) *Recorder {
	os.MkdirAll(recordDir, 0755)
	return &Recorder{
		cfg:      cfg,
		db:       database,
		sessions: make(map[string]*DesktopSession),
	}
}

func (r *Recorder) StartRecording() (string, error) {
	sessionID := r.generateSessionID()
	startTime := time.Now()

	outputPath := filepath.Join(recordDir, fmt.Sprintf("%s.mp4", sessionID))

	cmd := buildFFmpegCmd(outputPath)
	if cmd == nil {
		return "", fmt.Errorf("无法启动桌面录制：ffmpeg 或录制方式不可用")
	}

	err := cmd.Start()
	if err != nil {
		return "", fmt.Errorf("启动录制失败: %v", err)
	}

	r.mu.Lock()
	r.sessions[sessionID] = &DesktopSession{
		SessionID:  sessionID,
		StartTime:  startTime,
		PID:        cmd.Process.Pid,
		OutputPath: outputPath,
		IsActive:   true,
		cmd:        cmd,
	}
	r.mu.Unlock()

	log.Printf("[Recorder] 开始桌面录制: %s, PID: %d", sessionID, cmd.Process.Pid)
	return sessionID, nil
}

func (r *Recorder) StopRecording(sessionID string) error {
	r.mu.Lock()
	session, ok := r.sessions[sessionID]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("会话不存在: %s", sessionID)
	}

	if !session.IsActive {
		r.mu.Unlock()
		return nil
	}

	session.IsActive = false
	cmd := session.cmd
	r.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
		}
	}

	log.Printf("[Recorder] 停止桌面录制: %s", sessionID)
	return nil
}

func buildFFmpegCmd(outputPath string) *exec.Cmd {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		log.Printf("[Recorder] ffmpeg 未安装")
		return nil
	}

	display := os.Getenv("DISPLAY")
	if display == "" {
		display = ":0"
	}

	videoSize := "1920x1080"
	screenInfo, err := exec.Command("xdpyinfo", "-display", display).Output()
	if err == nil {
		lines := string(screenInfo)
		for _, line := range strings.Split(lines, "\n") {
			if strings.Contains(line, "dimensions:") {
				parts := strings.Split(line, " ")
				for _, part := range parts {
					if strings.Contains(part, "x") && !strings.Contains(part, "pixels") {
						videoSize = strings.TrimSpace(part)
						break
					}
				}
			}
		}
	}

	log.Printf("[Recorder] 录制分辨率: %s, 显示器: %s", videoSize, display)

	// 使用force_original_aspect_ratio=decrease保持原始比例缩放，然后用pad填充黑边
	scaleFilter := fmt.Sprintf("scale=%d:%d:force_original_aspect_ratio=decrease,pad=%d:%d:(ow-iw)/2:(oh-ih)/2:color=black", maxWidth, maxHeight, maxWidth, maxHeight)
	log.Printf("[Recorder] 缩放并填充到: %dx%d", maxWidth, maxHeight)

	cmd := exec.Command("ffmpeg",
		"-f", "x11grab",
		"-framerate", fmt.Sprintf("%d", frameRate),
		"-video_size", videoSize,
		"-i", display,
		"-vf", scaleFilter,
		"-c:v", "libx264",
		"-preset", "medium",
		"-crf", fmt.Sprintf("%d", videoQuality),
		"-pix_fmt", "yuv420p",
		"-g", "60",
		"-an",
		"-y",
		outputPath,
	)

	return cmd
}

func (r *Recorder) generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x_%d", b, time.Now().Unix())
}

func (r *Recorder) GetUnsyncedRecordings() ([]string, error) {
	var recordings []string
	files, err := filepath.Glob(filepath.Join(recordDir, "*.mp4"))
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		if info.Size() > 0 && info.ModTime().Add(uploadInterval).Before(time.Now()) {
			r.mu.Lock()
			active := false
			for _, s := range r.sessions {
				if s.IsActive && s.OutputPath == file {
					active = true
					break
				}
			}
			r.mu.Unlock()
			if !active {
				recordings = append(recordings, file)
			}
		}
	}

	return recordings, nil
}

func (r *Recorder) DeleteRecording(filePath string) error {
	return os.Remove(filePath)
}

func (r *Recorder) IsFFmpegAvailable() bool {
	_, err := exec.LookPath("ffmpeg")
	return err == nil
}

func IsScreenLocked() bool {
	display := os.Getenv("DISPLAY")
	if display == "" {
		display = ":0"
	}

	if _, err := exec.LookPath("xfce4-screensaver-command"); err == nil {
		output, err := exec.Command("xfce4-screensaver-command", "-q").Output()
		if err == nil && strings.Contains(string(output), "The screensaver is active") {
			return true
		}
	}

	if _, err := exec.LookPath("loginctl"); err == nil {
		sessionID := os.Getenv("XDG_SESSION_ID")
		if sessionID != "" {
			output, err := exec.Command("loginctl", "show-session", "-p", "LockedHint", sessionID).Output()
			if err == nil && strings.Contains(string(output), "LockedHint=yes") {
				return true
			}
		}
	}

	if _, err := exec.LookPath("gdbus"); err == nil {
		output, err := exec.Command("gdbus", "call", "--session", "--dest", "org.gnome.ScreenSaver", "--object-path", "/org/gnome/ScreenSaver", "--method", "org.gnome.ScreenSaver.GetActive").Output()
		if err == nil && strings.Contains(string(output), "true") {
			return true
		}
	}

	if _, err := exec.LookPath("xssstate"); err == nil {
		output, err := exec.Command("xssstate", "-s").Output()
		if err == nil && strings.Contains(string(output), "locked") {
			return true
		}
	}

	if _, err := exec.LookPath("qdbus"); err == nil {
		output, err := exec.Command("qdbus", "org.kde.screensaver", "/ScreenSaver", "org.freedesktop.ScreenSaver.GetActive").Output()
		if err == nil && strings.Contains(string(output), "true") {
			return true
		}
	}

	return false
}
