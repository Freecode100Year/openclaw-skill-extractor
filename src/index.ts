import { unzipSync, zipSync, strToU8, strFromU8 } from "fflate";
import YAML from "yaml";

interface Env { ASSETS: Fetcher }

type FileMap = Record<string, Uint8Array>;

const TEXT_EXT = /\.(md|txt|sh|bash|zsh|fish|py|js|mjs|cjs|ts|tsx|jsx|json|ya?ml|toml|ini|env|ps1|rb|pl|php|go|rs|java|kt|swift|sql)$/i;
const SCRIPT_EXT = /\.(sh|bash|zsh|fish|py|js|mjs|cjs|ts|ps1|rb|pl|php|go|rs)$/i;

function json(data: unknown, status=200) {
  return new Response(JSON.stringify(data, null, 2), {
    status, headers: {"content-type":"application/json; charset=utf-8"}
  });
}
function safePath(p:string) {
  return !p.startsWith("/") && !p.includes("..") && !p.includes("\\");
}
function isText(bytes:Uint8Array) {
  const sample = bytes.subarray(0, Math.min(bytes.length, 4096));
  let bad=0;
  for (const b of sample) if (b === 0 || (b < 9) || (b > 13 && b < 32)) bad++;
  return bad < Math.max(2, sample.length * .02);
}
function decode(bytes:Uint8Array) { return new TextDecoder().decode(bytes); }

function parseSkill(md:string) {
  let frontmatter:any = {};
  let body = md;
  if (md.startsWith("---")) {
    const end = md.indexOf("\n---", 3);
    if (end > 0) {
      const raw = md.slice(4, end);
      try { frontmatter = YAML.parse(raw) || {}; } catch {}
      body = md.slice(end + 4).trimStart();
    }
  }
  const fenced = [...body.matchAll(/```([a-zA-Z0-9_+-]*)\n([\s\S]*?)```/g)].map((m,i)=>({
    index:i+1, language:(m[1]||"text").toLowerCase(), code:m[2].trim()
  }));
  const shellCommands = fenced
    .filter(x => ["bash","sh","shell","zsh","fish","powershell","ps1"].includes(x.language))
    .flatMap(x => x.code.split("\n").map(s=>s.trim()).filter(Boolean));
  const envVars = [...new Set([
    ...[...md.matchAll(/\b[A-Z][A-Z0-9_]{2,}\b/g)].map(m=>m[0]),
    ...[...md.matchAll(/\$\{?([A-Z][A-Z0-9_]{2,})\}?/g)].map(m=>m[1])
  ])].filter(v => !["SKILL","README","HTTP","HTTPS","JSON","YAML","API"].includes(v)).sort();
  const baseDirRefs = [...md.matchAll(/\{baseDir\}[\/\\]([^\s`"'<>]+)/g)].map(m=>m[1]);
  return {frontmatter, body, fenced, shellCommands, envVars, baseDirRefs};
}


type Severity = "low"|"medium"|"high"|"critical";
type Finding = {
  severity: Severity;
  category: string;
  rule: string;
  file: string;
  line?: number;
  evidence: string;
  recommendation: string;
};

const SECURITY_RULES:{severity:Severity,category:string,rule:string,re:RegExp,recommendation:string}[] = [
  {severity:"critical",category:"destructive",rule:"recursive-delete",re:/\brm\s+-[^\n]*r[^\n]*f\b|\bRemove-Item\b[^\n]*-Recurse[^\n]*-Force/i,recommendation:"阻止自动执行；人工确认删除目标和路径范围。"},
  {severity:"critical",category:"execution",rule:"download-pipe-shell",re:/\b(curl|wget)\b[^\n|]*\|\s*(sh|bash|zsh|fish)\b/i,recommendation:"不要直接执行网络下载内容；先固定版本、校验哈希并审查。"},
  {severity:"critical",category:"execution",rule:"dynamic-eval",re:/\b(eval|exec)\s*\(|\beval\s+["'$`]?|\bFunction\s*\(/i,recommendation:"动态执行可能绕过静态审查；默认拒绝或隔离运行。"},
  {severity:"critical",category:"credentials",rule:"credential-exfiltration",re:/(API[_-]?KEY|TOKEN|PASSWORD|SECRET|PRIVATE[_-]?KEY)[^\n]{0,120}(curl|wget|fetch|requests\.|axios|http)/i,recommendation:"疑似读取密钥后向外发送；默认阻断并人工审计。"},
  {severity:"high",category:"privilege",rule:"privilege-escalation",re:/\b(sudo|su\s+-|doas)\b/i,recommendation:"需要主机高权限；默认禁止，除非明确批准。"},
  {severity:"high",category:"filesystem",rule:"sensitive-path-write",re:/(\/etc\/|\/root\/|~\/\.ssh\/|~\/\.config\/|\.bashrc|\.zshrc|authorized_keys|crontab)/i,recommendation:"可能修改系统/登录配置或持久化；隔离并检查具体写入。"},
  {severity:"high",category:"persistence",rule:"persistence",re:/\b(crontab|systemctl\s+enable|launchctl|schtasks|rc\.local)\b/i,recommendation:"检测到持久化行为；默认阻止自动安装。"},
  {severity:"high",category:"network",rule:"reverse-shell-pattern",re:/(\/dev\/tcp\/|nc\s+.*-[elp]|ncat\s+.*-[elp]|bash\s+-i|socat\s+.*EXEC)/i,recommendation:"疑似反向 Shell/远程控制模式；默认拒绝。"},
  {severity:"high",category:"permissions",rule:"world-writable",re:/\bchmod\s+(777|a\+w)\b/i,recommendation:"避免全局可写权限；改为最小权限。"},
  {severity:"medium",category:"network",rule:"external-network",re:/\b(curl|wget)\b\s+https?:\/\/|fetch\s*\(\s*["']https?:\/\/|requests\.(get|post|put|delete)\s*\(\s*["']https?:\/\//i,recommendation:"列出目标域名并由用户批准网络访问。"},
  {severity:"medium",category:"dependency",rule:"package-install",re:/\b(npm|pnpm|yarn|pip|pip3|uv|apt|apt-get|brew|cargo|gem)\s+(install|add)\b/i,recommendation:"依赖安装会执行第三方代码；固定版本并审查来源。"},
  {severity:"medium",category:"filesystem",rule:"broad-file-access",re:/(\bfind\s+\/|\bglob\b.*\*\*|os\.walk\(\s*["']\/|readdir.*\/)/i,recommendation:"可能遍历大量文件；限制到 Skill 工作目录。"},
  {severity:"medium",category:"secrets",rule:"secret-env-reference",re:/\b(AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|SSH_AUTH_SOCK|DATABASE_URL)\b/i,recommendation:"需要敏感环境变量；只按需注入，禁止打印到日志。"},
  {severity:"low",category:"obfuscation",rule:"encoded-content",re:/\b(base64\s+-d|atob\s*\(|fromBase64|Buffer\.from\([^)]*,\s*["']base64["'])/i,recommendation:"编码内容可能隐藏真实行为；解码后再次扫描。"},
];

function lineOf(text:string, idx:number) {
  return text.slice(0, idx).split("\n").length;
}
function evidenceAt(text:string, idx:number) {
  const start = Math.max(0, text.lastIndexOf("\n", idx) + 1);
  const end0 = text.indexOf("\n", idx);
  const end = end0 < 0 ? text.length : end0;
  return text.slice(start,end).trim().slice(0,240);
}
function scanSecurity(files:FileMap) {
  const findings:Finding[] = [];
  const domains = new Set<string>();
  for (const [file, bytes] of Object.entries(files)) {
    if (!safePath(file) || !isText(bytes)) continue;
    const text = decode(bytes);
    for (const r of SECURITY_RULES) {
      const flags = r.re.flags.includes("g") ? r.re.flags : r.re.flags + "g";
      const rx = new RegExp(r.re.source, flags);
      for (const m of text.matchAll(rx)) findings.push({
        severity:r.severity, category:r.category, rule:r.rule, file,
        line:lineOf(text,m.index||0), evidence:evidenceAt(text,m.index||0),
        recommendation:r.recommendation
      });
    }
    for (const m of text.matchAll(/https?:\/\/([a-z0-9.-]+)/ig)) domains.add(m[1].toLowerCase());
  }
  const weights:Record<Severity,number>={low:2,medium:8,high:20,critical:40};
  const raw = findings.reduce((n,f)=>n+weights[f.severity],0);
  const score = Math.min(100, raw);
  const level:Severity = findings.some(x=>x.severity==="critical") ? "critical"
    : findings.some(x=>x.severity==="high") ? "high"
    : findings.some(x=>x.severity==="medium") ? "medium" : "low";
  const decision = level==="critical" ? "BLOCK"
    : level==="high" ? "MANUAL_REVIEW"
    : level==="medium" ? "REVIEW" : "ALLOW_WITH_CAUTION";
  return {
    score, level, decision,
    findingCount:findings.length,
    findings,
    externalDomains:[...domains].sort(),
    guarantees:[
      "本分析器不会执行 Skill 中的 Shell/Python/JavaScript 等代码。",
      "静态扫描不能证明 Skill 安全；混淆代码、运行时下载和供应链依赖仍需人工审计。",
      "高风险 Skill 应在最小权限沙箱中运行，并限制网络、文件系统和密钥访问。"
    ]
  };
}


type CallEdge = {
  from: string;
  to: string;
  kind: string;
  line: number;
  evidence: string;
  resolved: boolean;
};
type Entrypoint = {
  skillFile: string;
  target: string;
  line: number;
  evidence: string;
  resolved: boolean;
};

function normalizeRel(baseDir:string, target:string) {
  target = target.replace(/^["'`]|["'`]$/g,"").replace(/\{baseDir\}/g, baseDir || ".");
  target = target.replace(/^\.\//,"");
  const parts:string[] = [];
  for (const p of target.split("/")) {
    if (!p || p === ".") continue;
    if (p === "..") {
      if (!parts.length) return null;
      parts.pop();
    } else parts.push(p);
  }
  return parts.join("/");
}

function scriptRefsInText(text:string, file:string, baseDir:string):CallEdge[] {
  const edges:CallEdge[] = [];
  const patterns:{kind:string,re:RegExp,group:number}[] = [
    {kind:"shell-script", re:/(?:^|[;&|]\s*|\s)(?:bash|sh|zsh|fish)\s+((?:\{baseDir\}|\.{0,2}\/)?[A-Za-z0-9_./-]+\.(?:sh|bash|zsh|fish))\b/gm, group:1},
    {kind:"python-script", re:/(?:^|[;&|]\s*|\s)(?:python3?|uv\s+run\s+python)\s+((?:\{baseDir\}|\.{0,2}\/)?[A-Za-z0-9_./-]+\.py)\b/gm, group:1},
    {kind:"node-script", re:/(?:^|[;&|]\s*|\s)(?:node|bun|deno\s+run)\s+((?:\{baseDir\}|\.{0,2}\/)?[A-Za-z0-9_./-]+\.(?:js|mjs|cjs|ts))\b/gm, group:1},
    {kind:"powershell-script", re:/(?:powershell|pwsh)[^\n]*?(?:-File\s+)?((?:\{baseDir\}|\.{0,2}\/)?[A-Za-z0-9_./-]+\.ps1)\b/gim, group:1},
    {kind:"direct-script", re:/(?:^|\s)((?:\{baseDir\}|\.\/)[A-Za-z0-9_./-]+\.(?:sh|bash|zsh|fish|py|js|mjs|cjs|ts|ps1|rb|pl|php))\b/gm, group:1},
    {kind:"python-subprocess", re:/subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*(?:\[[^\]]*?["']([^"']+\.(?:sh|py|js))["']|["']([^"']+\.(?:sh|py|js))["'])/g, group:1},
    {kind:"node-child-process", re:/(?:execFile|spawn|fork)\s*\(\s*["']([^"']+\.(?:sh|py|js|mjs|cjs|ts))["']/g, group:1},
  ];
  for (const p of patterns) {
    for (const m of text.matchAll(p.re)) {
      const raw = (m[p.group] || m[p.group+1] || "").trim();
      if (!raw) continue;
      const target = normalizeRel(baseDir, raw);
      if (!target) {
        edges.push({from:file,to:raw,kind:"path-escape",line:lineOf(text,m.index||0),evidence:evidenceAt(text,m.index||0),resolved:false});
        continue;
      }
      edges.push({from:file,to:target,kind:p.kind,line:lineOf(text,m.index||0),evidence:evidenceAt(text,m.index||0),resolved:false});
    }
  }
  return edges;
}

function skillEntrypoints(skillFile:string, body:string, baseDir:string, files:FileMap):Entrypoint[] {
  return scriptRefsInText(body, skillFile, baseDir).map(e => ({
    skillFile,
    target:e.to,
    line:e.line,
    evidence:e.evidence,
    resolved:Object.prototype.hasOwnProperty.call(files,e.to)
  }));
}

function analyzeCallGraph(files:FileMap, skills:any[]) {
  const edges:CallEdge[] = [];
  const entrypoints:Entrypoint[] = [];
  const executableFiles = Object.keys(files).filter(n => SCRIPT_EXT.test(n) && safePath(n));
  const findings:Finding[] = [];

  for (const s of skills) {
    for (const ep of skillEntrypoints(s.skillFile, s.instructionBody, s.directory==="." ? "" : s.directory, files)) {
      entrypoints.push(ep);
      if (!ep.resolved) findings.push({
        severity:"high",category:"call-chain",rule:"unresolved-skill-entrypoint",
        file:s.skillFile,line:ep.line,evidence:ep.evidence,
        recommendation:`Skill 调用了无法在包内解析的脚本 ${ep.target}；可能依赖宿主文件或运行时下载，必须人工确认。`
      });
    }
  }

  for (const file of executableFiles) {
    const bytes = files[file];
    if (!isText(bytes)) continue;
    const content = decode(bytes);
    const base = file.includes("/") ? file.slice(0,file.lastIndexOf("/")) : "";
    const local = scriptRefsInText(content,file,base);
    for (const e of local) {
      e.resolved = Object.prototype.hasOwnProperty.call(files,e.to);
      edges.push(e);
      if (!e.resolved && e.kind !== "path-escape") findings.push({
        severity:"medium",category:"call-chain",rule:"unresolved-script-call",
        file,line:e.line,evidence:e.evidence,
        recommendation:`脚本继续调用 ${e.to}，但包内不存在；检查 PATH、宿主文件、安装阶段或网络下载来源。`
      });
      if (e.kind === "path-escape") findings.push({
        severity:"critical",category:"filesystem",rule:"script-path-escape",
        file,line:e.line,evidence:e.evidence,
        recommendation:"脚本引用路径试图越出 Skill 目录；默认阻断。"
      });
    }

    // Execution APIs that can hide the real command.
    const dynamicRules:{severity:Severity,rule:string,re:RegExp,rec:string}[] = [
      {severity:"critical",rule:"python-shell-true",re:/subprocess\.(?:run|Popen|call|check_output)\s*\([\s\S]{0,400}?shell\s*=\s*True/gi,rec:"shell=True 会扩大命令注入面；改为参数数组并禁用 shell。"},
      {severity:"critical",rule:"os-system",re:/\bos\.system\s*\(/g,rec:"os.system 通过 Shell 执行；改为 subprocess 参数数组并验证输入。"},
      {severity:"critical",rule:"node-exec-dynamic",re:/\bexec(?:Sync)?\s*\(\s*(?!["'`][^$`]*["'`])/g,rec:"动态 child_process.exec 可能产生命令注入；使用 execFile/spawn 参数数组。"},
      {severity:"high",rule:"shell-variable-command",re:/\b(?:bash|sh)\s+-c\s+["'`][^"'`]*\$(?:\{|[A-Za-z_])/g,rec:"Shell -c 拼接变量存在注入风险；严格白名单并避免拼接命令。"},
      {severity:"high",rule:"unsafe-forwarded-args",re:/\beval\b[^\n]*["'`]?.*\$(?:@|\*)|\b(?:bash|sh)\s+-c[^\n]*\$(?:@|\*)/g,rec:"用户/上游参数被再次解释；不要 eval，逐参数传递并校验。"},
      {severity:"high",rule:"powershell-expression",re:/\bInvoke-Expression\b|\biex\b/g,rec:"PowerShell 动态表达式执行；默认阻断或重写为固定命令。"},
      {severity:"high",rule:"runtime-download-exec",re:/(?:requests\.|fetch\(|curl|wget)[\s\S]{0,500}?(?:exec\(|eval\(|subprocess|child_process|chmod\s+\+x|bash|sh\s+)/gi,rec:"脚本疑似下载内容后继续执行；必须固定来源、版本、哈希并人工审计。"}
    ];
    for (const r of dynamicRules) {
      for (const m of content.matchAll(r.re)) findings.push({
        severity:r.severity,category:"execution",rule:r.rule,file,
        line:lineOf(content,m.index||0),evidence:evidenceAt(content,m.index||0),
        recommendation:r.rec
      });
    }
  }

  // Trace reachable scripts from each Skill entrypoint.
  const adjacency = new Map<string,string[]>();
  for (const e of edges) {
    if (!e.resolved) continue;
    if (!adjacency.has(e.from)) adjacency.set(e.from,[]);
    adjacency.get(e.from)!.push(e.to);
  }

  const chains:any[] = [];
  for (const ep of entrypoints) {
    if (!ep.resolved) continue;
    const stack:{node:string,path:string[]}[] = [{node:ep.target,path:[ep.skillFile,ep.target]}];
    const seen = new Set<string>();
    while (stack.length) {
      const cur = stack.pop()!;
      const key = cur.path.join(" -> ");
      if (seen.has(key) || cur.path.length > 10) continue;
      seen.add(key);
      const next = adjacency.get(cur.node) || [];
      if (!next.length) chains.push({skillFile:ep.skillFile,path:cur.path});
      for (const n of next) {
        if (cur.path.includes(n)) {
          chains.push({skillFile:ep.skillFile,path:[...cur.path,n],cycle:true});
          continue;
        }
        stack.push({node:n,path:[...cur.path,n]});
      }
    }
  }

  // package manager lifecycle hooks are part of the effective execution chain.
  for (const [file,bytes] of Object.entries(files)) {
    if (!/(^|\/)package\.json$/i.test(file) || !isText(bytes)) continue;
    try {
      const pkg = JSON.parse(decode(bytes));
      const lifecycle = ["preinstall","install","postinstall","prepare","prepublish","prepublishOnly"];
      for (const name of lifecycle) if (pkg?.scripts?.[name]) findings.push({
        severity:"high",category:"supply-chain",rule:`npm-${name}-hook`,file,
        evidence:`"${name}": "${String(pkg.scripts[name]).slice(0,220)}"`,
        recommendation:"安装依赖时可能自动执行生命周期脚本；默认使用 --ignore-scripts，审计后再单独批准。"
      });
    } catch {}
  }

  return {entrypoints,edges,chains,findings};
}

function analyze(files:FileMap) {
  const names = Object.keys(files).filter(safePath).sort();
  const skillNames = names.filter(n => /(^|\/)SKILL\.md$/i.test(n));
  const skills = skillNames.map(path => {
    const md = decode(files[path]);
    const parsed = parseSkill(md);
    const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
    const localFiles = names.filter(n => !dir || n.startsWith(dir + "/"));
    const scripts = localFiles.filter(n => SCRIPT_EXT.test(n)).map(n => ({
      path:n, size:files[n].length, content:isText(files[n]) ? decode(files[n]) : null
    }));
    const referencedFiles = parsed.baseDirRefs.map(ref => dir ? `${dir}/${ref}` : ref);
    return {
      skillFile:path,
      directory:dir || ".",
      name: parsed.frontmatter?.name || dir.split("/").pop() || "unknown",
      description: parsed.frontmatter?.description || "",
      frontmatter:parsed.frontmatter,
      instructionBody:parsed.body,
      codeBlocks:parsed.fenced,
      shellCommands:parsed.shellCommands,
      environmentVariables:parsed.envVars,
      referencedFiles,
      scripts,
      files:localFiles.map(n=>({path:n,size:files[n].length,text:TEXT_EXT.test(n)&&isText(files[n])}))
    };
  });
  const baseSecurity = scanSecurity(files);
  const callGraph = analyzeCallGraph(files, skills);
  const mergedFindings = [...baseSecurity.findings, ...callGraph.findings];
  const weights:Record<Severity,number>={low:2,medium:8,high:20,critical:40};
  const score = Math.min(100, mergedFindings.reduce((n,f)=>n+weights[f.severity],0));
  const level:Severity = mergedFindings.some(x=>x.severity==="critical") ? "critical"
    : mergedFindings.some(x=>x.severity==="high") ? "high"
    : mergedFindings.some(x=>x.severity==="medium") ? "medium" : "low";
  const decision = level==="critical" ? "BLOCK"
    : level==="high" ? "MANUAL_REVIEW"
    : level==="medium" ? "REVIEW" : "ALLOW_WITH_CAUTION";
  const security = {
    ...baseSecurity,
    score, level, decision,
    findingCount:mergedFindings.length,
    findings:mergedFindings,
    callGraph
  };
  return {
    skillCount:skills.length,
    totalFiles:names.length,
    security,
    skills,
    warnings:[
      ...(skills.length===0 ? ["未找到 SKILL.md"] : []),
      ...names.filter(n=>!safePath(n)).map(n=>`忽略不安全路径: ${n}`)
    ]
  };
}

async function githubRepo(url:string):Promise<FileMap> {
  const u = new URL(url);
  if (u.hostname !== "github.com") throw new Error("目前 URL 导入仅支持 github.com");
  const parts = u.pathname.split("/").filter(Boolean);
  if (parts.length < 2) throw new Error("GitHub URL 无效");
  const [owner, repoRaw] = parts;
  const repo = repoRaw.replace(/\.git$/,"");
  let branch = "main";
  let subdir = "";
  const treePos = parts.indexOf("tree");
  if (treePos >= 0 && parts[treePos+1]) {
    branch = parts[treePos+1];
    subdir = parts.slice(treePos+2).join("/");
  }
  // GitHub codeload is public-repo only in this starter.
  const resp = await fetch(`https://codeload.github.com/${owner}/${repo}/zip/refs/heads/${encodeURIComponent(branch)}`, {
    headers: {"user-agent":"openclaw-skill-extractor"}
  });
  if (!resp.ok && branch === "main") {
    const retry = await fetch(`https://codeload.github.com/${owner}/${repo}/zip/refs/heads/master`, {headers:{"user-agent":"openclaw-skill-extractor"}});
    if (!retry.ok) throw new Error(`GitHub 下载失败: ${resp.status}`);
    return filterGithubZip(new Uint8Array(await retry.arrayBuffer()), subdir);
  }
  if (!resp.ok) throw new Error(`GitHub 下载失败: ${resp.status}`);
  return filterGithubZip(new Uint8Array(await resp.arrayBuffer()), subdir);
}

function filterZipFiles(bytes:Uint8Array):FileMap {
  const raw = unzipSync(bytes);
  const out:FileMap = {};
  for (const [name,data] of Object.entries(raw)) {
    if (!name.endsWith("/") && safePath(name)) out[name] = data;
  }
  return out;
}

async function clawHubSkill(url:string):Promise<FileMap> {
  const u = new URL(url);
  if (u.protocol !== "https:" || u.hostname.toLowerCase() !== "clawhub.ai") {
    throw new Error("ClawHub URL 必须来自 https://clawhub.ai");
  }
  const parts = u.pathname.split("/").filter(Boolean).map(decodeURIComponent);
  const [ownerHandle, kind, slug] = parts;
  if (parts.length !== 3 || kind !== "skills" || !ownerHandle || !slug) {
    throw new Error("ClawHub URL 格式应为 https://clawhub.ai/<发布者>/skills/<技能名>");
  }
  const download = new URL("https://clawhub.ai/api/v1/download");
  download.searchParams.set("slug", slug);
  download.searchParams.set("ownerHandle", ownerHandle);
  const resp = await fetch(download, {headers:{"user-agent":"openclaw-skill-extractor"}});
  if (!resp.ok) throw new Error(`ClawHub 下载失败: ${resp.status}`);
  const type = resp.headers.get("content-type") || "";
  if (!type.includes("application/zip")) throw new Error("ClawHub 返回的不是技能 ZIP 文件");
  return filterZipFiles(new Uint8Array(await resp.arrayBuffer()));
}

async function urlRepo(url:string):Promise<FileMap> {
  const hostname = new URL(url).hostname.toLowerCase();
  if (hostname === "github.com") return githubRepo(url);
  if (hostname === "clawhub.ai") return clawHubSkill(url);
  throw new Error("URL 导入仅支持公开 GitHub 仓库或 ClawHub Skill 页面");
}

function filterGithubZip(bytes:Uint8Array, subdir:string):FileMap {
  const raw = unzipSync(bytes);
  const out:FileMap = {};
  for (const [name,data] of Object.entries(raw)) {
    const slash = name.indexOf("/");
    if (slash < 0) continue;
    let rel = name.slice(slash+1);
    if (!rel || rel.endsWith("/")) continue;
    if (subdir) {
      if (!rel.startsWith(subdir.replace(/\/$/,"") + "/") && rel !== subdir) continue;
      rel = rel.slice(subdir.length).replace(/^\//,"");
    }
    if (rel && safePath(rel)) out[rel] = data;
  }
  return out;
}

function extractedZip(files:FileMap) {
  const analysis:any = analyze(files);
  const out:FileMap = {};
  for (const skill of analysis.skills) {
    out[`extracted/${skill.name}/SKILL.md`] = strToU8(
      `---\n${YAML.stringify(skill.frontmatter).trim()}\n---\n\n${skill.instructionBody}`
    );
    for (const s of skill.scripts) if (s.content !== null) {
      const base = s.path.split("/").pop()!;
      out[`extracted/${skill.name}/scripts/${base}`] = strToU8(s.content);
    }
    out[`extracted/${skill.name}/analysis.json`] = strToU8(JSON.stringify(skill,null,2));
  }
  out["analysis.json"] = strToU8(JSON.stringify(analysis,null,2));
  return zipSync(out, {level:6});
}

export default {
  async fetch(request:Request, env:Env):Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/analyze" && request.method === "POST") {
        const ct = request.headers.get("content-type") || "";
        let files:FileMap = {};
        if (ct.includes("application/json")) {
          const body:any = await request.json();
          if (!body.url) return json({error:"缺少 url"},400);
          files = await urlRepo(body.url);
        } else {
          const bytes = new Uint8Array(await request.arrayBuffer());
          files = unzipSync(bytes);
        }
        return json(analyze(files));
      }
      if (url.pathname === "/api/extract" && request.method === "POST") {
        const ct = request.headers.get("content-type") || "";
        let files:FileMap = {};
        if (ct.includes("application/json")) {
          const body:any = await request.json();
          files = await urlRepo(body.url);
        } else files = unzipSync(new Uint8Array(await request.arrayBuffer()));
        return new Response(extractedZip(files), {
          headers:{
            "content-type":"application/zip",
            "content-disposition":'attachment; filename="openclaw-skill-extracted.zip"'
          }
        });
      }
      return env.ASSETS.fetch(request);
    } catch (e:any) {
      return json({error:e?.message || "处理失败"},500);
    }
  }
};
