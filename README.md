# OpenClaw Skill Extractor

Cloudflare Worker + Static Assets 网页工具。

## 在线使用

https://openclaw-skill-extractor.sj9292008133.workers.dev

## 能做什么
- 输入公开 GitHub 仓库或 `tree/<branch>/<path>` URL
- 输入 ClawHub Skill URL（例如 `https://clawhub.ai/apidojo-io/skills/instagram-scraper`）
- 上传 ZIP
- 自动发现所有 `SKILL.md`
- 解析 YAML frontmatter
- 提取 Markdown fenced code blocks / shell 命令
- 扫描环境变量名
- 收集 Skill 同目录脚本
- 输出 `analysis.json`
- 一键下载拆解后的 ZIP

## 部署

```bash
npm install
npm run dev
```

登录 Cloudflare 后：

```bash
npx wrangler login
npm run deploy
```

## 安全设计
此版本只“读取和静态分析”，不会执行任何 Skill 脚本。
不要在网页中执行上传 Skill 的 shell/Python/JS。
公开 GitHub 下载使用 codeload；ClawHub 使用其公开下载接口；私有仓库尚未接 GitHub OAuth。


## 安全审计
自动检测并评分：
- `curl/wget | sh`
- `eval/exec` 动态执行
- `sudo` / 权限提升
- `rm -rf` 等破坏性操作
- `/etc`、`~/.ssh`、shell rc、crontab 等敏感路径
- 持久化行为
- 反向 Shell 特征
- 外部网络访问和域名
- 包管理器安装依赖
- 高价值环境变量 / Token 引用
- Base64 等潜在混淆行为

风险等级：`LOW / MEDIUM / HIGH / CRITICAL`
决策建议：`ALLOW_WITH_CAUTION / REVIEW / MANUAL_REVIEW / BLOCK`

### 重要
静态扫描只能发现已知模式，不能证明代码安全。此工具永不执行被分析 Skill。


## v0.3：Skill 调用脚本安全 / Execution Chain

安全分析不再只看单个文件，而是追踪实际执行链：

`SKILL.md → run.sh → helper.py → child_process/subprocess → 下一层脚本`

新增：
- 从 `SKILL.md` 解析 `{baseDir}/scripts/...`、bash/python/node/pwsh 等入口
- 递归建立本地脚本调用图与完整调用链
- 未解析脚本/宿主 PATH 调用告警
- 路径越界调用阻断
- Python `shell=True` / `os.system`
- Node `child_process.exec` 动态执行
- `bash -c` + 变量、`eval $@` 等命令注入模式
- PowerShell `Invoke-Expression`
- 下载后执行模式
- npm `preinstall/install/postinstall/prepare` 生命周期脚本
- 循环调用检测
- 调用链风险合并回 Skill 最终风险等级

### 执行安全原则

1. 分析器永不执行上传 Skill。
2. “包内没有找到调用目标”不能视为安全，反而应提升风险。
3. 依赖安装脚本也是代码执行，应纳入调用链。
4. 静态扫描无法完全解析动态生成的命令，因此 High/Critical 必须人工复核。
5. 真正执行第三方 Skill 时应采用最小权限沙箱、网络 allowlist、只读文件系统和按需密钥注入。
