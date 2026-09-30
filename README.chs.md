# hyKBridge

```
== HyKBridge by HYrecovery & HoshinoSumi from teko.IO SisTemS! ==
== Under MIT Open Source License ==
```

**一条局域网桥，让你的电脑够得着一台大多数时间都在睡觉的电子书阅读器。**
方向是反的：**设备主动来找你** —— 它按定时器醒来，在局域网里找到你的机器，拉走一条
命令，执行，然后继续睡。

不用云，不用账号，不用第三方服务器。同一局域网里两台机器就够。

在已越狱的 Kindle Paperwhite 3（KUAL + Kindle Python 3.9）上实测通过。

---

## 为什么这么设计

挂起的设备**没有网络栈** —— 它睡着的时候没有任何东西能连上它。所以方向只能反过来：

* **设备是主动方**：它醒来、发现主机、把活儿拉走；
* **主机是被动服务端**：它等着、做鉴权、然后应答。

主机返回的每一个响应都带签名，设备**在执行任何东西之前先验签**，因为这些命令在设备上
是以 `root` 跑的。真正的威胁是局域网里冒出来的假服务端，而签名挡的就是它。

## 工作方式

```
        配对一次                        之后，一直如此
   ┌──────────────────┐        ┌────────────────────────────────────┐
   │ 设备：KUAL       │        │ 设备醒来（RTC 闹钟）                │
   │  "Show Pairing   │        │   → 找主机（记住的 IP，             │
   │   Code" → 6 位码 │        │     否则听 :8093 的 UDP 广播）      │
   │        ↓         │        │   → GET /next?dev=…&hold=25        │
   │ 主机：pair --code│        │   → 验 X-Host-Sig（HMAC）           │
   │        ↓         │        │   → 执行它 / 存下文件                │
   │ 共享密钥         │        │   → POST /result                    │
   │ + device_id      │        │   → 装下一次闹钟，睡觉               │
   └──────────────────┘        └────────────────────────────────────┘
```

* **发现主机** —— 设备先试配对时记下的主机地址（所以主机地址从来不需要手填），
  失败再听主机的 UDP 广播（`255.255.255.255:8093`，每 2 秒一个包）。仅限局域网，
  超时都很短。
* **响应的 body 本身就是命令。** 没有信封，命令不套 JSON。
* **飞行模式直接短路整个循环** —— 无线关了就轮询、不装闹钟、不唤醒。判据是无线开关
  本身，绝不看 `wlan0` 状态：刚恢复的那一瞬间网卡还没关联上，把它读成"飞行模式"就会
  导致设备再也不装闹钟，从此再也醒不过来。

## 安全模型

| 方向 | 凭据 | 挡什么 |
|---|---|---|
| 主机 → 设备 | `X-Host-Sig = HMAC-SHA256(secret, body)` | 局域网里的假"主机"往设备里灌 root 命令 |
| 设备 → 主机 | `X-Dev`、`X-Ts`、`X-Sig = HMAC(secret, dev\|ts\|method\|path)` | 假设备来掏你的队列；`X-Ts` 提供防重放（±300 秒） |
| 首次接触 | 设备屏幕上显示的 6 位码，**一次性**，5 分钟有效，最多试 5 次，定长比较 | 有人跟你抢配对 |

文件传输对 `sha256(内容)` 签名，先写 `.part` 再原子改名。密钥从不打印 —— 只打印长度和
指纹。

## 安装

### 1. 设备（已越狱、带 KUAL 和 Kindle Python 3 的 Kindle）

把 `device/` 目录整体复制到 Kindle 上，成为 `extensions/hyKBridge/`，例如用 USB：

```
<kindle>/extensions/hyKBridge/{config.xml,menu.json,bin/,server/}
```

然后在 KUAL 里：**hyKBridge → Shell: Start**（这一步同时会在防火墙里开端口 ——
Kindle 的 `INPUT` 策略是 `DROP`，新端口必须显式放行；该规则只在运行时生效，重启即消失）。设备服务监听 **8090**。

菜单里还有 **Shell: Stop / Restart**、**Show Status**、**Show Log**，以及 pulse / 保持常亮开关。

### 2. 主机（任何有 Node 18+ 的机器）

```bash
node host/hyKBridge.mjs serve        # HTTP 在 8091/8092 + UDP 广播
```

### 3. 配对一次

| | |
|---|---|
| 设备上 | KUAL → **hyKBridge → Show Pairing Code**（屏幕上出现 6 位数字） |
| 主机上 | `node host/hyKBridge.mjs pair --kindle <设备IP> --code 123456` |

### 4. 用起来

```bash
node host/hyKBridge.mjs exec "df -h /mnt/us"      # 在设备上执行命令
node host/hyKBridge.mjs push ./book.mobi           # 传文件到 /documents
node host/hyKBridge.mjs list                       # 队列 / 结果
node host/hyKBridge.mjs result <job-id>            # 读结果
node host/hyKBridge.mjs status                     # 已配对设备、端口、计数
```

设备上 **hyKBridge → Pulse: Start** 开始"醒来-轮询-睡觉"循环
（`state/pulse-interval`，默认 120 秒）。Pulse 从不强制挂起：它只装 RTC 闹钟，让系统
自己决定什么时候睡，所以你用设备的时候永远不会被打断。

## 接口

| 方法 | 路径 | 鉴权 | 用途 |
|---|---|---|---|
| GET | `/__hello` | 无 | 发现标记（`{"app":"hyKBridge",…}`） |
| GET | `/next?dev=&hold=25` | HMAC | 长轮询；**200 + 命令 body**，或 204 |
| POST | `/result?job=` | HMAC | 回传输出，清除任务 |
| GET | `/file/<job>` | HMAC | 下载排队的文件（对它的 sha256 签名） |
| POST | `/api/pair` | 6 位码 | 引导：用码换设备密钥 |

## 自己验证

```bash
node host/selftest.mjs
```

在本地同时扮演两端：没凭据 401、时间戳过期 401、密钥不对 401、长轮询真的会挂住、
body 就是命令、改一个字节签名就废、结果被存下来且任务被清掉。

期望输出：`RESULT: 10 passed, 0 failed`。

`exec` / `push` / `result` 的横幅走 **stderr**，所以 stdout 依然可以安全管道；
想彻底关掉就设 `HYKBRIDGE_QUIET=1`。

### 给已经装好的设备升级

服务运行中也能直接推文件——设备服务提供 `POST /api/put?path=…`（带 token 鉴权，
写入范围锁在 `/mnt/us`），推完在 KUAL 点 **Shell: Restart** 就生效。这个包就是这么
开发出来的：本地改、推送、重启、再跑一遍 `selftest.mjs`。

## 目录结构

```
host/hyKBridge.mjs        主机应用（单文件，零 npm 依赖）
host/selftest.mjs         协议自测
device/config.xml         KUAL 扩展清单
device/menu.json          KUAL 菜单
device/server/hyKBridge.py    设备服务：执行 / 文件 / 书籍 / 插件 / 配对
device/bin/hyKBridge-pulse.py 醒来-轮询-睡觉的客户端
device/bin/banner.sh          版权横幅（被所有脚本 source）
device/bin/*.sh               启动 / 停止 / 重启 / 状态 / 日志 / 配对码 / 保持常亮
```

## 许可证

MIT —— 见 [LICENSE](LICENSE)。

*English: [README.md](README.md)*
