package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/red-team/agent/config"
	"github.com/red-team/agent/collector"
	"github.com/red-team/agent/db"
	"github.com/red-team/agent/recorder"
	"github.com/red-team/agent/sync"
)

var version = "1.0.0"

func main() {
	serverURL := flag.String("server", "", "管理端服务器地址")
	flag.Parse()

	if *serverURL == "" {
		log.Fatal("Usage: agent --server http://server:8000")
	}

	cfg := config.New(*serverURL)

	database, err := db.New("agent.db")
	if err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}
	defer database.Close()

	coll := collector.New(database)
	syncer := sync.New(cfg, database)
	rec := recorder.New(cfg, database)
	uploader := recorder.NewUploader(cfg)

	socketServer := collector.NewSocketServer(database, coll)
	if err := socketServer.Start(); err != nil {
		log.Fatalf("[Agent] Socket服务器启动失败: %v", err)
	}
	defer socketServer.Stop()

	log.Printf("[Agent] 启动，版本: %s", version)
	log.Printf("[Agent] ClientID: %s", cfg.ClientID)
	log.Printf("[Agent] 服务端: %s", cfg.ServerURL)
	log.Printf("[Agent] 实时捕获Socket: /tmp/red-agent.sock")
	log.Printf("[Agent] 桌面录屏模块已加载")

	var currentSessionID string
	var wasLocked bool

	if rec.IsFFmpegAvailable() {
		isLocked := recorder.IsScreenLocked()
		if isLocked {
			log.Println("[Agent] 检测到锁屏状态，暂不启动录屏")
			wasLocked = true
		} else {
			sessionID, err := rec.StartRecording()
			if err != nil {
				log.Printf("[Agent] 启动桌面录制失败: %v", err)
			} else {
				currentSessionID = sessionID
				log.Printf("[Agent] 桌面录制已启动，会话ID: %s", sessionID)
			}
		}
	} else {
		log.Printf("[Agent] ffmpeg 不可用，跳过桌面录制")
	}

	log.Println("[Agent] 启动时立即发送测试心跳...")
	if err := syncer.Heartbeat(); err != nil {
		log.Printf("[Agent] 启动心跳测试失败: %v", err)
	} else {
		log.Printf("[Agent] 启动心跳测试成功！")
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	recordTicker := time.NewTicker(60 * time.Second)
	defer recordTicker.Stop()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Println("[Agent] 主循环启动，等待ticker触发...")

	for {
		select {
		case <-sigChan:
			log.Println("[Agent] 收到退出信号")
			if currentSessionID != "" {
				rec.StopRecording(currentSessionID)
				log.Printf("[Agent] 已停止录制: %s", currentSessionID)
			}
			return
		case <-recordTicker.C:
			if rec.IsFFmpegAvailable() && currentSessionID != "" {
				isLocked := recorder.IsScreenLocked()
				if isLocked {
					log.Printf("[Agent] 录制时长达到60秒，但检测到锁屏状态，停止录屏")
					if err := rec.StopRecording(currentSessionID); err != nil {
						log.Printf("[Agent] 停止录制失败: %v", err)
					}
					currentSessionID = ""
					wasLocked = true
				} else {
					log.Printf("[Agent] 录制时长达到60秒，切换录制片段")
					if err := rec.StopRecording(currentSessionID); err != nil {
						log.Printf("[Agent] 停止录制失败: %v", err)
					}
					sessionID, err := rec.StartRecording()
					if err != nil {
						log.Printf("[Agent] 启动新录制失败: %v", err)
						currentSessionID = ""
					} else {
						currentSessionID = sessionID
						log.Printf("[Agent] 新录制已启动，会话ID: %s", sessionID)
					}
				}
			}
		case <-ticker.C:
			log.Println("[Agent] ticker触发，开始执行循环任务")

			if rec.IsFFmpegAvailable() {
				isLocked := recorder.IsScreenLocked()
				if isLocked && !wasLocked && currentSessionID != "" {
					log.Println("[Agent] 检测到锁屏，停止录屏")
					if err := rec.StopRecording(currentSessionID); err != nil {
						log.Printf("[Agent] 停止录制失败: %v", err)
					}
					currentSessionID = ""
					wasLocked = true
				} else if !isLocked && wasLocked {
					log.Println("[Agent] 检测到解锁，恢复录屏")
					sessionID, err := rec.StartRecording()
					if err != nil {
						log.Printf("[Agent] 启动新录制失败: %v", err)
						currentSessionID = ""
					} else {
						currentSessionID = sessionID
						log.Printf("[Agent] 新录制已启动，会话ID: %s", sessionID)
					}
					wasLocked = false
				} else if isLocked && wasLocked {
					log.Println("[Agent] 保持锁屏状态，不录屏")
				}
			}

			log.Println("[Agent] 执行Collect...")
			collectDone := make(chan error, 1)
			go func() {
				collectDone <- coll.Collect()
			}()
			select {
			case err := <-collectDone:
				if err != nil {
					log.Printf("[Agent] 收集数据失败: %v", err)
				} else {
					log.Println("[Agent] Collect完成")
				}
			case <-time.After(60 * time.Second):
				log.Println("[Agent] Collect超时(60s)，强制继续")
			}

			log.Println("[Agent] 执行Sync...")
			if err := syncer.Sync(); err != nil {
				log.Printf("[Agent] 同步失败: %v", err)
			} else {
				log.Println("[Agent] Sync完成")
			}

			log.Println("[Agent] 执行Heartbeat...")
			if err := syncer.Heartbeat(); err != nil {
				log.Printf("[Agent] 心跳失败: %v", err)
			} else {
				log.Printf("[Agent] %s 心跳正常", time.Now().Format("15:04:05"))
			}

			log.Println("[Agent] 执行录制上传...")
			if err := uploadRecordings(rec, uploader); err != nil {
				log.Printf("[Agent] 上传录制失败: %v", err)
			} else {
				log.Println("[Agent] 录制上传完成")
			}

			log.Println("[Agent] 循环任务完成")
		}
	}
}

func uploadRecordings(rec *recorder.Recorder, uploader *recorder.Uploader) error {
	recordings, err := rec.GetUnsyncedRecordings()
	if err != nil {
		return err
	}

	if len(recordings) == 0 {
		return nil
	}

	log.Printf("[Agent] 发现 %d 个待上传录制", len(recordings))

	for _, filePath := range recordings {
		if err := uploader.UploadRecording(filePath); err != nil {
			log.Printf("[Agent] 上传失败: %s - %v", filePath, err)
			continue
		}

		if err := rec.DeleteRecording(filePath); err != nil {
			log.Printf("[Agent] 删除录制文件失败: %v", err)
		}
	}

	return nil
}
