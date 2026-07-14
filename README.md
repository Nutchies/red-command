# Red Command（红队运维管理系统）
Red Command 是一款综合性安全运维管理平台，提供资产管理、工具管理、录屏监控等功能。

## 功能特性

### 🗂️ 资产管理
- 单位层级目录树管理
- 自定义添加单位和子单位
- 资产IP列表管理
- Excel/JSON批量导入资产
- 资产隶属单位关联

### 💬 作战聊天室
- 实时消息发送与接收（WebSocket）
- 表情符号支持
- 图片上传与预览
- 文件上传与下载
- 消息引用回复
- 成员选择与管理

### 🎥 录屏监控
- 桌面自动录屏
- 锁屏状态自动停止录屏
- 解锁自动恢复录屏
- 录制文件加密上传
- 录制片段自动分割（60秒/段）

### 🔐 安全特性
- HTTPS加密通信
- JWT身份认证
- 密码加密存储
- 视频文件加密传输

### 📊 其他功能
- 用户分组管理
- 客户端状态监控
- 动作记录审计
- 渗透测试结果管理


## 项目结构

```
red_command/
├── agent/                    # Go语言客户端
│   ├── collector/            # 数据采集模块
│   ├── config/               # 配置管理
│   ├── db/                   # 本地数据库
│   ├── recorder/             # 录屏模块
│   ├── sync/                 # 数据同步模块
│   ├── main.go               # Agent入口
│   └── go.mod                # Go依赖
├── server/                   # 后端服务
│   ├── app/                  # 应用代码
│   │   ├── api/              # API路由
│   │   ├── core/             # 核心配置
│   │   ├── db/               # 数据库连接
│   │   ├── models/           # 数据模型
│   │   ├── services/         # 业务服务
│   │   └── videos/           # 加密视频存储
│   ├── web/                  # 前端代码
│   │   ├── src/              # Vue源码
│   │   └── index.html        # 主页面
│   ├── main.py               # 后端入口
│   └── requirements.txt      # Python依赖
└── .gitignore                # Git忽略配置
```

## 安装部署

### 环境要求

- Python 3.8+
- Go 1.21+
- FFmpeg (录屏功能)
- Linux (推荐)

### 后端安装

```bash
# 进入后端目录
cd server

# 创建虚拟环境
python -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt

# 初始化数据库
python init_db.py

# 启动服务
python main.py
```

服务将在 `https://localhost:8443` 启动（HTTPS）。

### 前端安装

前端已集成在后端 `web/index.html` 中，无需额外安装。

### Agent编译

```bash
# 进入Agent目录
cd agent

# 编译
go build -o agent .

# 运行
./agent --server https://your-server:8443
```

## 使用说明

### 默认账号

- **用户名**: admin
- **密码**: admin

### 资产管理

1. 登录系统后点击左侧"资产管理"菜单
2. 左侧显示单位层级目录树
3. 点击单位节点查看该单位下的资产列表
4. 右键节点可添加子单位或在此单位下添加资产

### 作战聊天室

1. 点击左侧"作战聊天室"菜单
2. 点击"+ 创建房间"创建新聊天室
3. 选择聊天室成员后创建
4. 支持发送文本、表情、图片、文件
5. 点击消息下方"回复"按钮引用消息

### 录屏功能

Agent运行后自动启动录屏，支持：
- 锁屏自动停止录屏
- 解锁自动恢复录屏
- 每60秒自动分割录制片段

## 配置说明

### 后端配置

后端配置位于 `server/app/core/config.py`：

```python
class Settings:
    SECRET_KEY: str = "your-secret-key"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DB_URL: str = "sqlite:///redcommand.db"
    SSL_CERT_PATH: str = "cert/server.crt"
    SSL_KEY_PATH: str = "cert/server.key"
```

### Agent配置

通过命令行参数指定：

```bash
./agent --server https://your-server:8443
```

## 安全注意事项

1. **HTTPS**: 所有通信均采用HTTPS加密
2. **密码**: 使用bcrypt加密存储
3. **视频**: 上传视频使用AES加密存储
4. **权限**: 不同用户组有不同操作权限

## 开发说明

### 添加新功能

1. 在 `server/app/models/models.py` 添加数据库模型
2. 在 `server/app/models/schemas.py` 添加Pydantic模型
3. 在 `server/app/api/routes.py` 添加API路由
4. 在 `server/web/index.html` 添加前端页面

### 测试

```bash
# 运行后端测试
cd server
python -m pytest

# 编译Agent测试
cd agent
go build -o agent .
```

## 贡献

欢迎提交Issue和Pull Request！

---

**注意**: 本项目仅供安全研究和教育目的使用，请遵守相关法律法规。
