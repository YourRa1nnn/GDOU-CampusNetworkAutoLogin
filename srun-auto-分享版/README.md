# srun-portal-autologin

深澜（srun）校园网网页认证的自动登录与掉线重连程序，运行在一台常开的 Windows 电脑上。
程序直接调用认证服务器的 HTTP 接口完成认证，不改动路由器固件，也不依赖路由器支持插件。

适用于这类场景：校园网需要浏览器跳转认证，希望认证由一台常开设备代劳，
路由器后面的所有设备（手机、电视、米家设备等）保持在线。

## 功能

- **掉线重登**：周期性探测上网通路，确认已被下线后立即重新认证
- **定时检查**：每天若干固定时间点各检查一次；关机或休眠错过的时间点在开机后补跑
- **失败退避**：登录失败按 5s / 15s / 60s / 300s 递增重试，避免高频请求
- **崩溃自愈**：守护脚本发现主程序退出后自动拉起
- **本地控制台**：网页界面修改参数、查看实时日志、手动触发检查或登录
- **单实例保护**：重复启动时后启动的进程直接退出，不产生第二次认证
- **默认不主动注销**：可按需开启「定时退出登录 + 重新登录」

## 环境要求

| 项目 | 要求 |
| --- | --- |
| 系统 | Windows（启动、自启脚本为 .bat / .vbs） |
| Python | 3.7 及以上，仅使用标准库，无需 pip 安装依赖 |
| 硬件 | 一台长期开机的电脑，且它的上网出口即需要认证的出口 |

核心逻辑 `srun_portal.py` 不依赖 Windows 专有接口，Linux / macOS 下可手动运行（无 .bat / .vbs 部分）。

## 工作原理

```
每 N 秒（默认 25s）
   └─ GET http://connect.rom.miui.com/generate_204
        ├─ 返回 204 ──────────────────► 在线，等待下一轮
        └─ 其他结果（302 / 200 / 超时）
             └─ GET /cgi-bin/rad_user_info
                  ├─ error = ok ──────► 校园网侧仍在线，判定为上游故障，不重登
                  └─ not_online_error ► 确认被下线，立即重新认证
```

判定掉线需要两个条件同时成立（上网不通 **且** 校园网侧未在线），因此单次丢包不会触发重登。
网络不通时重试间隔降为 3 秒，恢复后回到正常探测间隔。

## 快速开始

1. 安装 Python 3，安装时勾选 `Add python.exe to PATH`。
2. 把 `config.json.example` 复制为 `config.json`（也可以在控制台保存设置时自动生成）。
3. 双击 `设置开机自启.vbs`，程序在后台启动，浏览器打开 <http://127.0.0.1:8787/>。
4. 在「账号设置」里填写认证服务器、`ac_id`、`theme`、学号、密码，点「保存设置」。
5. 点「立即检查」，状态显示在线即配置完成。

需要填的三个认证参数可以从认证页地址里取得：未认证状态下用浏览器打开任意 http 网页（或
`http://connect.rom.miui.com/generate_204`），会跳转到类似

```
http://10.123.0.1/srun_portal_pc?ac_id=1&theme=pro&wlanuserip=10.x.x.x&...
```

的地址，其中 `10.123.0.1` 是 `portal_host`，`ac_id=1` 与 `theme=pro` 分别对应 `ac_id` 和 `theme`。

常用操作：

| 操作 | 方式 |
| --- | --- |
| 查看当前状态 | 双击 `状态检测.vbs`（只读，弹窗展示，看完关闭即可） |
| 打开控制台 | 双击 `打开控制台.bat` |
| 临时前台运行 | 双击 `启动.bat`，关闭窗口即停止 |
| 取消开机自启并停止 | 双击 `取消开机自启.vbs` |

## 配置项

配置文件为 `config.json`，也可以在控制台里修改。控制台只监听 `127.0.0.1`。

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `username` | 空 | 学号 / 上网账号 |
| `password` | 空 | 上网密码，明文保存 |
| `portal_host` | 空 | 认证服务器地址，如 `10.123.0.1` |
| `ac_id` | `1` | 认证页地址中的 `ac_id` |
| `theme` | `pro` | 认证页地址中的 `theme` |
| `check_interval_seconds` | `25` | 探测间隔。小于 10 秒会明显增加流量与日志量 |
| `fail_threshold` | `3` | 连续失败达到该次数后，重试间隔由 3 秒放宽到 10 秒 |
| `fast_retry_seconds` | `3` | 探测失败后的重试间隔 |
| `internet_probe_url` | `http://connect.rom.miui.com/generate_204` | 判断能否上网的探测地址，期望返回 204 |
| `probe_timeout_seconds` | `6` | 单次请求超时 |
| `daily_check_times` | `["06:00","15:30"]` | 定时检查时间点 |
| `catch_up_window_minutes` | `120` | 错过的时间点在开机后多久内仍补跑 |
| `enable_active_logout` | `false` | 是否在定时检查时先注销再登录 |
| `retry_backoff_seconds` | `[5,15,60,300]` | 登录失败的重试间隔序列 |
| `web_bind` / `web_port` | `127.0.0.1` / `8787` | 控制台监听地址与端口 |
| `log_max_bytes` / `log_keep_files` | `1048576` / `3` | 日志轮转阈值与保留份数 |

`config.json.example` 里额外的 `_说明` 字段程序会忽略，可以删除。

## 认证协议实现

程序按浏览器实际发出的请求实现，各参数与加密细节如下。

```
1) GET /cgi-bin/get_challenge?callback=<cb>&username=<学号>&ip=<出口IP>&_=<13位毫秒>
   响应给出 challenge（下称 token）与 client_ip

2) 本地计算
   hmd5   = HMAC-MD5(key = token, msg = 密码)
   info   = '{SRBX1}' + 变体base64( XEncode( JSON{username,password,ip,acid,enc_ver:'srun_bx1'}, token ) )
   chksum = SHA1( token+username + token+hmd5 + token+ac_id + token+ip
                  + token+n + token+type + token+info )

3) GET /cgi-bin/srun_portal?action=login&username=..&password={MD5}<hmd5>&info=<info>
       &chksum=<chksum>&ac_id=..&ip=..&n=200&type=1&os=Windows 10&name=Windows&double_stack=0

4) GET /cgi-bin/rad_user_info?callback=<cb>&_=<13位毫秒>
   error=ok 表示在线，not_online_error 表示已被下线

5) GET /cgi-bin/rad_user_dm?ip=..&username=..&time=<秒>&unbind=1
       &sign=SHA1(time+username+ip+unbind+time)          # 注销，默认不使用
```

实现时需要注意：

- base64 使用深澜自定义字母表
  `LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA`，不是标准字母表。
- `XEncode` 为 TEA 变体，`delta = 0x9E3779B9`，轮数 `6 + 52/(n+1)`，大小端按字（word）组织。
- `chksum` 拼接的是 `token + 参数值` 交替形式，漏掉任何一个 `token` 都会校验失败。
- 所有接口以 JSONP 形式返回，需要剥掉 `callback(...)` 外壳。
- `callback` 建议使用 `jQuery<随机数>_<13位毫秒>` 形式，`_` 参数必须是 13 位毫秒时间戳；
  传短整数会返回 `{"error":"bad_request_parameters"}`。
- 密码在 `info` 中可被持有 `token` 的一方逆推出来（XEncode 是对称算法），因此抓包文件等同于明文密码。

`协议自检.bat` / `python srun_portal.py --selftest` 可以用一份抓包数据离线校验上述实现：
填入 `srun_portal.py` 中 `SELFTEST` 的 `token`、`ip`、`expect`（浏览器实际发出的完整登录地址）
和 `expect_hmd5`，程序会重新拼装登录地址并与 `expect` 逐字节比对。

## 命令行

```bat
python srun_portal.py              启动（含网页控制台）
python srun_portal.py --check      检查一次并输出状态
python srun_portal.py --status     查询认证状态（输出 JSON）
python srun_portal.py --login      立即登录
python srun_portal.py --selftest   用抓包数据离线自检
python srun_portal.py --no-gui     不启动网页控制台
cscript //nologo 状态检测.vbs console            状态检测（命令行输出，不弹窗）
cscript //nologo 状态检测.vbs save C:\a.txt      状态检测并写入文本
```

## 文件说明

```
srun_portal.py        主程序：协议实现、探测、调度、退避、日志、内置控制台
config.json.example   配置模板，复制为 config.json 后填写
config.json           实际配置（含密码，已在 .gitignore 中排除）
启动.bat              前台启动
后台启动.vbs          隐藏窗口启动一次
后台守护.vbs          守护脚本，主程序退出后自动拉起
设置开机自启.vbs      注册开机自启（启动文件夹快捷方式）并立即启动
取消开机自启.vbs      取消开机自启并停止程序
状态检测.vbs          一次性状态检测（程序是否运行 / 认证是否在线 / 自启是否开启）
打开控制台.bat        打开 http://127.0.0.1:8787/
协议自检.bat          离线校验协议实现
logs/                 运行日志，按天分文件
.gitignore            排除 config.json、logs/ 等本地文件
```

## 常见问题

**登录返回 `bad_request_parameters`**
`_` 参数不是 13 位毫秒时间戳，或 `callback` 不是 `jQuery<数字>_<数字>` 形式。

**登录返回 `chksum error` / 校验失败**
`chksum` 拼接顺序或 `info` 加密结果与实际不符。用 `协议自检` 与真实抓包逐字节比对定位。

**认证成功但状态仍显示掉线**
程序的判断依据是 `generate_204` 是否返回 204。若学校对 204 探测地址做了拦截，
可把 `internet_probe_url` 换成其他返回 204 的地址。

**控制台打不开**
端口被占用。修改 `config.json` 的 `web_port`，或关闭占用该端口的程序。

**会不会因为频繁请求触发学校风控**
探测请求发往 `generate_204` 地址，不会命中认证服务器；只有在上网不通时才查询
`rad_user_info`。重新认证仅在「上网不通且校园网侧未在线」时发起，且失败后按退避重试。
默认探测间隔 25 秒，对应每天约 2 MB 探测流量；改为 5 秒会升至约 12 MB，日志也会很快被轮转。

**抓包文件可以一起提交吗**
不可以。`login.har`、`logout.har`、`curl.txt` 等文件中，`info` 参数配合 `token` 可离线解出明文密码，
同时还包含账号、出口 IP、设备 MAC 等信息。

## 已知限制

- 只实现深澜网页 Portal 认证。802.1X、PPPoE、需要专用客户端（加密 UDP）的网络不适用。
- 认证页若启用了验证码、滑块或自定义加密算法，需要按新的抓包调整实现。
- 依赖「认证会话绑定在路由器出口」这一前提（NAT 后按出口 IP 认证）。
  若学校按终端逐个认证，本程序只能让运行它的那台电脑上线。
- 密码以明文保存在 `config.json`，控制台仅监听本地回环地址。
- 使用前请确认符合所在学校的网络使用规定。

## 许可

MIT，见 `LICENSE`。
