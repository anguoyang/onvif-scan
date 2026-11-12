# onvif-scan

[English](README.md)

**一条命令，找出局域网里所有 ONVIF 摄像头，并生成一份资产盘点报告。**

```sh
PYTHONPATH=src python3 -m onvifscan scan
# 或安装后（pip install .）：
onvifscan scan --user onvif_user
```

输出 JSON + 单文件 HTML 报告：每台摄像头的厂商、型号、固件、序列号、通道数，
每个 Profile 的编码/分辨率/帧率、PTZ 有无、时钟健康度，以及脱敏后的 RTSP
流地址（可直接交给流验收工具）。

v0.2 增加 Profile 可见源关联、Media1/Media2 编码器 options 声明、PTZ 节点声明及
预置位数量/名称。Media2 options 已按修订 D1 的直接子元素请求形状实现，
并通过 strict 模拟器端到端测试，保留浮点帧率声明。

未发布版增加独立视频源枚举：与 Profile 无关的物理源也通过
`GetVideoSources` / `GetVideoSourceConfigurations` 列出并标注未绑定
（Media2 无 GetVideoSources，只枚举配置）。多源只是证据，不作设备类型推断；
`channel_count` 仍只计 Profile 可见源。CSV 末尾增加设备级 `source_count` /
`unbound_source_count` 两列；diff 比对字段由六类增至七类（加 sources token 集合）。
字段与限制见 [能力字段说明](docs/v0.2-capabilities.md)。

## 它解决什么

交付与运维摄像头车队时，总要反复回答这些无聊但昂贵的问题：这个网里到底
有什么？那台是什么固件？为什么这台鉴权总失败？40 台里哪些没有 PTZ？
厂商工具只能一台一台看、还只认自家品牌。`onvif-scan` 对任何 ONVIF 设备
一次扫全网，并把答案写成集成商可以归档、可以交给客户的报告。

## 工作方式

1. **发现**：每张网卡发 WS-Discovery 组播 Probe；组播被过滤或跨 VLAN 时
   用 `--host` 定向探测。
2. **盘点**：逐台只读查询——GetSystemDateAndTime（先测设备时钟偏移：
   ONVIF 鉴权失败的头号原因是摄像头时钟不准，所以所有鉴权请求都按
   **设备时间**签名）、GetCapabilities/GetServices、GetDeviceInformation、
   GetHostname、GetNetworkInterfaces、Media/Media2 的 GetProfiles、
   GetStreamUri/GetSnapshotUri。
3. **发现项而不只是字段**：时钟偏移、无凭据信息泄露（老固件口径松）、
   XAddr 错位、只有 Media2 / 只有老 Media、凭据被拒、SOAP 响应畸形——
   每项有稳定 ID 和一句人话提示。
4. **接力验收**：每个取到流地址的 Profile 都给一条可直接粘贴的下一步命令
   `rkdoctor rtsp rtsp://user:***@…`（RK Edge Doctor 的流健康验收）。
   发现 → 验收，一条链。

## 安全与凭据红线（硬规矩）

- **全只读**：只有 `Get*` 查询，绝不改配置、绝不发 PTZ 移动命令。
- **绝不试默认口令、绝不带字典、绝不爆破**：只用你显式提供的凭据
  （`--user` / 环境变量 `ONVIFSCAN_PASSWORD` / `--creds` 按 IP/MAC 映射
  的文件），每台设备每份凭据只试一次，被拒即停——部分厂商有非法登录
  锁定，扫描器绝不能把你锁在自己的摄像头外面。
- **密码永不进输出**：流地址存脱敏形式，报告生成后还会再做一次密码
  子串擦除。
- **只扫描你拥有或有权管理的网络。** 离线运行、无遥测；组播 TTL 固定 1，
  不出本网段。

## 快速开始

```sh
git clone https://github.com/anguoyang/onvif-scan && cd onvif-scan

# 无凭据：发现 + 每台设备愿意公开给出的信息
PYTHONPATH=src python3 -m onvifscan scan

# 全网共用一个 ONVIF 用户（注意：很多摄像头的 ONVIF 用户与 Web 用户
# 是两套体系，需要在设备上单独建）
ONVIFSCAN_PASSWORD=... PYTHONPATH=src python3 -m onvifscan scan --user onvif_user

# 每台不同凭据
PYTHONPATH=src python3 -m onvifscan scan --creds creds.json

# 组播被过滤 / 已知地址定向
PYTHONPATH=src python3 -m onvifscan scan --host 192.168.3.64

# 定向目标很多时：文本文件一行一个 host[:发现端口]（# 注释与空行
# 忽略；可与 --host 混用）
PYTHONPATH=src python3 -m onvifscan scan --hosts cameras.txt
```

报告默认写到当前目录 `onvif-inventory.json` / `onvif-inventory.html`。
`examples/` 里有对着模拟设备生成的样例报告（明确标注 simulated）。

用于 cron 定时盘点时，可加 `--quiet`，终端只输出汇总行和报告路径；
JSON 与 HTML 报告仍按原方式生成：

```sh
PYTHONPATH=src python3 -m onvifscan scan --quiet
```

## CSV 导出与基线 diff

CSV 仅在显式指定 `--csv PATH` 时生成，可与 `--no-html`、`--quiet` 共存。
quiet 扫描仍只输出两行，末行 `reports:` 补上 CSV 路径。

```sh
PYTHONPATH=src python3 -m onvifscan scan --csv inventory.csv --no-html --quiet
PYTHONPATH=src python3 -m onvifscan diff old.json new.json
PYTHONPATH=src python3 -m onvifscan diff old.json new.json --json changes.json --quiet
```

CSV 使用 UTF-8+BOM 和固定表头，每行是一台设备 × 一个 Profile；无 Profile
的设备仍出一行，Profile 列为空。缺失值为空字符串，已知零个仍写 `0`。
`findings` 仅含排序、去重后以分号连接的 code，不含 detail。固定列顺序：

```text
ip,port,mac,manufacturer,model,firmware_version,hostname,level,profile_token,profile_name,media_gen,video_source_token,encoder_options_status,ptz_node_token,preset_count,channel_count,clock_offset_s,findings,source_count,unbound_source_count
```

末尾两列为设备级源统计：可见源总数与未绑定任何配置文件的源数，均来自独立
源枚举；`channel_count` 不变，仍只计 Profile 可见源。

diff 离线读取两份已经过 scan 擦除密码的 JSON 报告，不扫描、不联网、不取凭据。
两份输入均须为 `schema: 1`、`kind: "onvif_inventory"`；`tool_version` 不同
仅在 stderr 警告，不算设备变化。设备优先用小写归一化 MAC 匹配，无 MAC 才退回
IP；身份缺失或重复属于输入错误。同 MAC 换 IP 不算变化；从无 MAC 变为有 MAC
或反向变化会改变身份键，表现为消失＋新增。

只比七类字段：固件版本、level、Profile token/media_gen 对的集合、channel_count、
findings code 集合、services_declared namespace 集合、独立枚举的 sources token
集合。集合忽略顺序和重复项。
生成时间、扫描时长、detail 及其他设备/Profile 字段均不参与比对。diff 保留扫描
报告已有的密码擦除结果，不索取密码来清洗手工改写的输入文件。

终端输出 `diff: +A -R ~C =U`，分别表示新增、消失、变化和不变的设备数；
`--quiet` 下也只输出这一行。仅 `--json OUT` 才写 diff JSON 文件。
JSON 中 `added`/`removed` 是身份键数组，`unchanged` 是数量；`changed` 各项含
`key`、`identity_basis`（`mac`/`ip`）和 `changes: [{field, old, new}]`。
field 使用 JSON 路径式：`device_info.FirmwareVersion`、`level`、`profiles`、
`channel_count`、`findings.code`、`services_declared.namespace`。
Profile 集合写成排序后的 `{token, media_gen}` 对象数组；未知可选标量写 `null`，
缺失集合按空集合比较。

| 退出码 | 含义 |
| --- | --- |
| 0 | scan 正常完成，或 diff 无变化 |
| 1 | diff 检测到新增、消失或变化设备 |
| 2 | 参数/输入错误，包括文件不存在、JSON 非法、schema/kind 不符 |

cron 脚本须将 diff 的 **1 视为变化通知，不是执行失败**。

## 结果怎么读

逐台定级：**FULL**（身份+Profile 齐全）、**PARTIAL**（只有身份或能力）、
**DISCOVERED_ONLY**（只发现、无应答——多半是 ONVIF 没开或需要凭据而未给）、
**UNREACHABLE**。扫到 0 台时工具给的是提示而不是断言：现行固件普遍默认
关闭 ONVIF（海康 ≥5.5.0、Axis ≥5.40 都是默认关，且要单独建 ONVIF 用户），
Wi-Fi AP 也常过滤组播。厂商差异细节见 `docs/vendor-notes.md`。

## 验证状态（说实话）

v0.1。发现→盘点全链路已对三类模拟设备（严格/标准/老旧三种厂商行为，
模拟器在 `tests/` 里、CI 里跑）端到端验证，含时钟偏移鉴权的正反两例。
真实摄像头报告正在征集——在真实车队上跑一次并提一个 device report
issue，是目前最有价值的贡献。在第一批真机报告落地前，厂商行为覆盖请
按「模拟验证」理解，不要当作「现场验证」。

## 与 RK Edge Doctor 的关系

onvif-scan 回答「网里有什么」，`rkdoctor rtsp` 回答「这条流健不健康」，
两者组成摄像头验收链。[Site AI Gateway](https://site-ai-gateway.com)
面向安防与停车集成商的开源工具。

## 许可证

Apache-2.0。
