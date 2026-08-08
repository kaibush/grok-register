import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  ArrowRight,
  Cloud,
  Mail,
  RefreshCw,
  Save,
  Settings2,
  ShieldCheck,
} from "lucide-react";
import { api } from "@/lib/api";
import {
  Button,
  buttonVariants,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Label,
  PageHeader,
  Select,
  Switch,
  Toast,
} from "@/components/ui";

const PROVIDERS = [
  {
    value: "cloudflare",
    label: "Cloudflare 临时邮箱",
    description: "适合自建 Worker/API；可配置域名、鉴权方式和收信路径。",
  },
  {
    value: "duckmail",
    label: "DuckMail / Mail.tm",
    description: "通用临时邮箱接口；DuckMail 可填 API Key，Mail.tm 公共接口可留空。",
  },
  {
    value: "yyds",
    label: "YYDS 临时邮箱",
    description: "需要 YYDS API Key 或 JWT，可固定已验证收信域名。",
  },
  {
    value: "mailnest",
    label: "MailNest 迈巢 Outlook",
    description: "Outlook 临时邮箱服务，需要 API Key 和项目代码。",
  },
  {
    value: "outlookemail",
    label: "OutlookEmail 邮箱池",
    description: "支持外部 accounts 账号池或站内 temp 临时邮箱。",
  },
  {
    value: "cloudmail",
    label: "CloudMail 自建邮箱",
    description: "适合自建 cloud-mail，需要站点地址、管理员账号和域名。",
  },
];
export type SettingsSection = "registration" | "cpa" | "grok2api" | "mail" | "outlook";

const SECTION_META: Record<SettingsSection, { title: string; description: string }> = {
  registration: { title: "注册设置", description: "注册数量、代理、浏览器语言与运行方式。" },
  cpa: { title: "CPA / Auth", description: "配置 SSO 授权转换、Token 模式与 CPA 入库目标。" },
  grok2api: { title: "Grok2API", description: "维护本地授权目录、远程管理端与自动导入。" },
  mail: { title: "邮箱服务", description: "选择邮箱服务商并维护对应接口与访问凭据。" },
  outlook: { title: "Outlook 邮箱池", description: "配置账号池来源、分组、邮件读取与自动停用。" },
};
const TOKEN_MODES = [
  { value: "device_protocol", label: "协议 Device Flow" },
  { value: "device_browser", label: "浏览器 Device Flow" },
  { value: "auth_code", label: "授权码 Authorization Code" },
];
const OUTLOOK_SOURCES = [
  { value: "accounts", label: "外部账号池 accounts" },
  { value: "temp", label: "站内临时邮箱 temp" },
];
const OUTLOOK_PICK_MODES = [
  { value: "random", label: "随机选取" },
  { value: "sequential", label: "顺序选取" },
];
const CLOUDFLARE_AUTH_MODES = [
  { value: "none", label: "无需鉴权" },
  { value: "bearer", label: "Bearer Token" },
  { value: "x-api-key", label: "X-API-Key" },
  { value: "x-admin-auth", label: "管理员密码 X-Admin-Auth" },
  { value: "query-key", label: "URL 参数 key" },
];

function ToggleRow({
  title,
  description,
  checked,
  onCheckedChange,
}: {
  title: string;
  description?: string;
  checked: boolean;
  onCheckedChange: (value: boolean) => void;
}) {
  return (
    <div className="flex min-h-16 items-center justify-between gap-4 rounded-xl border bg-muted/35 px-3 py-3 sm:px-4">
      <div className="min-w-0">
        <div className="text-sm font-medium text-foreground">{title}</div>
        {description ? <div className="mt-0.5 text-xs leading-5 text-muted-foreground">{description}</div> : null}
      </div>
      <Switch checked={checked} onCheckedChange={onCheckedChange} label={title} />
    </div>
  );
}

function SectionIcon({ children }: { children: React.ReactNode }) {
  return (
    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-sky-50 text-sky-600">
      {children}
    </span>
  );
}

function ConfigField({
  config,
  onFieldChange,
  label,
  field,
  type = "text",
  placeholder = "",
  helper = "",
}: {
  config: Record<string, any>;
  onFieldChange: (key: string, value: any) => void;
  label: string;
  field: string;
  type?: string;
  placeholder?: string;
  helper?: string;
}) {
  return (
    <div className="min-w-0 space-y-2">
      <Label htmlFor={field}>{label}</Label>
      <Input
        id={field}
        type={type}
        inputMode={type === "number" ? "numeric" : undefined}
        autoComplete={type === "password" ? "new-password" : "off"}
        placeholder={placeholder}
        value={config[field] ?? ""}
        onChange={(event) =>
          onFieldChange(
            field,
            type === "number" && event.target.value !== ""
              ? Number(event.target.value)
              : event.target.value
          )
        }
      />
      {helper ? <p className="text-xs leading-5 text-muted-foreground">{helper}</p> : null}
    </div>
  );
}

export function SettingsPage({ section = "registration" }: { section?: SettingsSection }) {
  const [searchParams] = useSearchParams();
  const [config, setConfig] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<{ message: string; tone?: "default" | "success" | "error" }>({
    message: "",
  });

  const showToast = (message: string, tone: "default" | "success" | "error" = "default") => {
    setToast({ message, tone });
    window.setTimeout(() => setToast({ message: "" }), 2200);
  };

  const load = async () => {
    setLoading(true);
    try {
      const data = await api.getConfig();
      const requestedProvider = section === "mail" ? String(searchParams.get("provider") || "") : "";
      const validProvider = PROVIDERS.some((item) => item.value === requestedProvider) ? requestedProvider : "";
      setConfig({ ...(data.config || {}), ...(validProvider ? { email_provider: validProvider } : {}) });
    } catch (err: any) {
      showToast(err.message || "加载配置失败", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const setField = (key: string, value: any) => {
    setConfig((previous) => ({ ...previous, [key]: value }));
  };
  const fieldState = { config, onFieldChange: setField };
  const selectedProvider = PROVIDERS.find(
    (item) => item.value === (config.email_provider || "cloudflare")
  ) || PROVIDERS[0];

  const onSave = async () => {
    setSaving(true);
    try {
      const data = await api.saveConfig(config);
      setConfig(data.config || config);
      showToast(`已保存 ${data.changed?.length || 0} 项配置`, "success");
    } catch (err: any) {
      showToast(err.message || "保存失败", "error");
    } finally {
      setSaving(false);
    }
  };

  const meta = SECTION_META[section];

  return (
    <div className="space-y-5 sm:space-y-6">
      <PageHeader
        title={meta.title}
        description={meta.description}
        actions={
          <>
            <Button variant="outline" onClick={load} disabled={loading || saving}>
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} aria-hidden="true" />
              重新加载
            </Button>
            <Button onClick={onSave} disabled={saving || loading}>
              <Save className="h-4 w-4" aria-hidden="true" />
              {saving ? "保存中…" : "保存配置"}
            </Button>
          </>
        }
      />

      <div className="space-y-4">
        {section === "registration" ? (
        <Card>
          <CardHeader className="flex-row items-start gap-3">
            <SectionIcon><Settings2 className="h-5 w-5" aria-hidden="true" /></SectionIcon>
            <div>
              <CardTitle>基础与注册</CardTitle>
              <CardDescription>邮箱来源、代理、数量、并发和浏览器运行方式。</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2 sm:col-span-2">
              <Label htmlFor="email_provider">邮箱服务商</Label>
              <Select
                id="email_provider"
                value={config.email_provider || "cloudflare"}
                onChange={(event) => setField("email_provider", event.target.value)}
              >
                {PROVIDERS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
              </Select>
              <p className="text-xs leading-5 text-muted-foreground">{selectedProvider.description}</p>
            </div>
            <div className="flex flex-col gap-3 rounded-xl border border-sky-100 bg-sky-50/70 p-3 sm:col-span-2 sm:flex-row sm:items-center sm:justify-between sm:p-4">
              <div className="flex min-w-0 items-start gap-3">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-white text-sky-600 ring-1 ring-sky-100">
                  <Mail className="h-4 w-4" aria-hidden="true" />
                </span>
                <div className="min-w-0">
                  <div className="text-sm font-medium text-slate-900">配置 {selectedProvider.label}</div>
                  <p className="mt-0.5 text-xs leading-5 text-slate-500">
                    {selectedProvider.value === "outlookemail" ? "前往邮箱池页面配置接口、账号来源和自动停用。" : "前往邮箱服务页面填写该服务商需要的接口与凭据。"}
                  </p>
                </div>
              </div>
              <Link
                to={selectedProvider.value === "outlookemail" ? "/settings/outlook" : `/settings/mail?provider=${encodeURIComponent(selectedProvider.value)}`}
                className={buttonVariants({ variant: "outline", className: "w-full bg-white sm:w-auto" })}
              >
                前往设置
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </Link>
            </div>
            <ConfigField {...fieldState} label="网络代理" field="proxy" placeholder="http://127.0.0.1:7890" />
            <ConfigField {...fieldState}
              label="账号间隔（秒）"
              field="account_interval"
              placeholder="60-120"
              helper="支持固定秒数或区间；等待过程可随时停止。"
            />
            <ConfigField {...fieldState} label="注册数量" field="register_count" type="number" />
            <ConfigField {...fieldState} label="并发浏览器数" field="register_workers" type="number" />
            <ConfigField {...fieldState} label="日志级别" field="log_level" placeholder="info（普通）/ debug（详细）" />
            <div className="min-w-0 space-y-2">
              <Label htmlFor="browser_locale">浏览器界面语言</Label>
              <Select
                id="browser_locale"
                value={config.browser_locale || "en-US"}
                onChange={(event) => setField("browser_locale", event.target.value)}
              >
                <option value="en-US">English (en-US，推荐)</option>
                <option value="zh-CN">简体中文 (zh-CN)</option>
              </Select>
              <p className="text-xs leading-5 text-muted-foreground">
                固定注册页面语言，不跟随代理出口自动切换。
              </p>
            </div>
            <div className="space-y-3 sm:col-span-2">
              <ToggleRow
                title="注册后开启 NSFW"
                description="失败时不阻塞账号保存与 CPA 入库"
                checked={!!config.enable_nsfw}
                onCheckedChange={(value) => setField("enable_nsfw", value)}
              />
              <ToggleRow
                title="调试模式"
                description="强制单账号，结束后保留浏览器"
                checked={!!config.debug_mode}
                onCheckedChange={(value) => setField("debug_mode", value)}
              />
              <ToggleRow
                title="无头浏览器"
                description="后台运行且不显示窗口；Camoufox 会修正常见无头指纹，但无法保证不触发站点风控"
                checked={!!config.browser_headless}
                onCheckedChange={(value) => setField("browser_headless", value)}
              />
              <ToggleRow
                title="停止时关闭浏览器"
                description="收到停止请求后清理当前浏览器实例"
                checked={!!config.close_browser_on_stop}
                onCheckedChange={(value) => setField("close_browser_on_stop", value)}
              />
            </div>
          </CardContent>
        </Card>
        ) : null}

        {section === "cpa" || section === "grok2api" ? (
        <div className="space-y-4">
          {section === "cpa" ? (
          <Card>
            <CardHeader className="flex-row items-start gap-3">
              <SectionIcon><ShieldCheck className="h-5 w-5" aria-hidden="true" /></SectionIcon>
              <div>
                <CardTitle>授权转换</CardTitle>
                <CardDescription>注册完成后将 SSO 换为 CPA 与 Grok2API 所需凭据。</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <div className="sm:col-span-2">
                <ToggleRow
                  title="注册后自动 SSO → auth"
                  description="所有邮箱服务商都必须 CPA 状态为 success 才计注册成功，请保持开启"
                  checked={!!config.cpa_auto_add}
                  onCheckedChange={(value) => setField("cpa_auto_add", value)}
                />
              </div>
              <div className="space-y-2 sm:col-span-2">
                <Label htmlFor="cpa_token_mode">授权转换方式</Label>
                <Select
                  id="cpa_token_mode"
                  value={config.cpa_token_mode || "device_protocol"}
                  onChange={(event) => setField("cpa_token_mode", event.target.value)}
                >
                  {TOKEN_MODES.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                </Select>
              </div>
            </CardContent>
          </Card>
          ) : null}

          <div className="grid gap-4">
            {section === "cpa" ? (
            <Card>
              <CardHeader>
                <CardTitle>CPA 目标</CardTitle>
                <CardDescription>保存本地 CPA JSON，也可上传到远程 Management API。</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-4">
                <ConfigField {...fieldState} label="本地授权目录" field="cpa_auth_dir" />
                <ConfigField {...fieldState} label="远程 CPA 地址" field="cpa_remote_url" placeholder="http://host:8317" />
                <ConfigField {...fieldState} label="远程管理密钥" field="cpa_management_key" type="password" />
              </CardContent>
            </Card>
            ) : null}

            {section === "grok2api" ? (
            <Card>
              <CardHeader>
                <CardTitle>Grok2API 目标</CardTitle>
                <CardDescription>保存 Grok Build、Grok Web、Grok Console 三种 JSON，并通过管理员账号登录远程服务导入。</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-4">
                <ConfigField {...fieldState} label="本地授权目录" field="grok2api_auth_dir" />
                <ConfigField
                  {...fieldState}
                  label="远程 API 地址"
                  field="grok2api_remote_url"
                  placeholder="https://api.example.com"
                  helper="填写站点根地址，不要附加 /api/admin/v1"
                />
                <ConfigField {...fieldState} label="管理员账号" field="grok2api_remote_username" />
                <ConfigField {...fieldState} label="管理员密码" field="grok2api_remote_password" type="password" />
                <ToggleRow
                  title="转换成功后自动导入"
                  description="生成三种 Grok2API JSON 后立即登录远程管理端并逐个导入；导入结果单独记录"
                  checked={!!config.grok2api_auto_import}
                  onCheckedChange={(value) => setField("grok2api_auto_import", value)}
                />
              </CardContent>
            </Card>
            ) : null}
          </div>
        </div>
        ) : null}

        {section === "mail" ? (
        <Card>
          <CardHeader className="flex-row items-start gap-3">
            <SectionIcon><Cloud className="h-5 w-5" aria-hidden="true" /></SectionIcon>
            <div>
              <CardTitle>邮箱服务商凭证</CardTitle>
              <CardDescription>当前选择：{selectedProvider.label}。这里只显示该服务所需字段。</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div className="sm:col-span-2 rounded-xl border bg-muted/35 p-3 text-sm">
              <div className="font-medium">{selectedProvider.label}</div>
              <div className="mt-1 text-xs leading-5 text-muted-foreground">{selectedProvider.description}</div>
            </div>

            {selectedProvider.value === "duckmail" ? (
              <>
                <ConfigField {...fieldState} label="接口地址" field="duckmail_api_base" helper="DuckMail 默认 https://api.duckmail.sbs；Mail.tm 填 https://api.mail.tm" />
                <ConfigField {...fieldState} label="API Key" field="duckmail_api_key" type="password" helper="DuckMail 私有域需要；Mail.tm 公共接口可留空" />
              </>
            ) : null}

            {selectedProvider.value === "cloudflare" ? (
              <>
                <ConfigField {...fieldState} label="接口地址" field="cloudflare_api_base" helper="Cloudflare 临时邮箱 Worker/API 根地址" />
                <ConfigField {...fieldState} label="API Key / 管理员密码" field="cloudflare_api_key" type="password" />
                <div className="min-w-0 space-y-2">
                  <Label htmlFor="cloudflare_auth_mode">鉴权方式</Label>
                  <Select
                    id="cloudflare_auth_mode"
                    value={config.cloudflare_auth_mode || "none"}
                    onChange={(event) => setField("cloudflare_auth_mode", event.target.value)}
                  >
                    {CLOUDFLARE_AUTH_MODES.map((item) => (
                      <option key={item.value} value={item.value}>{item.label}</option>
                    ))}
                  </Select>
                </div>
                <ConfigField {...fieldState} label="全局访问密码" field="cloudflare_custom_auth" type="password" helper="对应 Worker PASSWORDS，发送到 X-Custom-Auth" />
                <ConfigField {...fieldState} label="收信域名" field="defaultDomains" helper="多个域名可用逗号或空格分隔" />
                <ConfigField {...fieldState} label="域名接口路径" field="cloudflare_path_domains" />
                <ConfigField {...fieldState} label="创建邮箱接口路径" field="cloudflare_path_accounts" />
                <ConfigField {...fieldState} label="获取 Token 接口路径" field="cloudflare_path_token" />
                <ConfigField {...fieldState} label="邮件列表接口路径" field="cloudflare_path_messages" />
              </>
            ) : null}

            {selectedProvider.value === "yyds" ? (
              <>
                <ConfigField {...fieldState} label="API Key" field="yyds_api_key" type="password" helper="API Key 与 JWT 至少填写一个" />
                <ConfigField {...fieldState} label="JWT" field="yyds_jwt" type="password" helper="填写 JWT 时优先使用 JWT 鉴权" />
                <ConfigField {...fieldState} label="固定收信域名" field="yyds_default_domain" helper="留空时自动选择已验证域名" />
              </>
            ) : null}

            {selectedProvider.value === "mailnest" ? (
              <>
                <ConfigField {...fieldState} label="API Key" field="mailnest_api_key" type="password" />
                <ConfigField {...fieldState} label="项目代码" field="mailnest_project_code" helper="默认 x-ai001" />
              </>
            ) : null}

            {selectedProvider.value === "cloudmail" ? (
              <>
                <ConfigField {...fieldState} label="站点地址" field="cloudmail_url" helper="自建 cloud-mail 根地址，不要附加 /api" />
                <ConfigField {...fieldState} label="管理员邮箱" field="cloudmail_admin_email" />
                <ConfigField {...fieldState} label="管理员密码" field="cloudmail_password" type="password" />
                <ConfigField {...fieldState} label="收信域名" field="defaultDomains" helper="多个域名可用逗号或空格分隔" />
              </>
            ) : null}

            {selectedProvider.value === "outlookemail" ? (
              <div className="flex flex-col gap-3 rounded-xl border border-sky-200 bg-sky-50 p-4 text-sm text-sky-700 sm:col-span-2 sm:flex-row sm:items-center sm:justify-between">
                <span>OutlookEmail 的账号池、临时邮箱和自动停用配置位于独立页面。</span>
                <Link to="/settings/outlook" className={buttonVariants({ variant: "outline", size: "sm", className: "bg-white" })}>
                  打开邮箱池设置
                  <ArrowRight className="h-4 w-4" aria-hidden="true" />
                </Link>
              </div>
            ) : null}
          </CardContent>
        </Card>
        ) : null}

        {section === "outlook" ? (
        <Card>
          <CardHeader className="flex-row items-start gap-3">
            <SectionIcon><Mail className="h-5 w-5" aria-hidden="true" /></SectionIcon>
            <div>
              <CardTitle>OutlookEmail 邮箱池</CardTitle>
              <CardDescription>接口、分组、选取方式与 Web 会话配置。</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <ToggleRow
                title="CPA 成功后停用 Outlook 邮箱"
                description="仅 accounts 来源生效；CPA 状态必须为 success，随后自动更新邮箱为 inactive"
                checked={!!config.outlookemail_disable_after_cpa_success}
                onCheckedChange={(value) =>
                  setField("outlookemail_disable_after_cpa_success", value)
                }
              />
            </div>
            <ConfigField {...fieldState}
              label="API Base"
              field="outlookemail_api_base"
              helper="Compose 可选服务使用 http://outlook-email:5000；外部服务填写其实际地址"
            />
            <ConfigField {...fieldState}
              label="API Key"
              field="outlookemail_api_key"
              type="password"
              helper="accounts 来源读取账号列表和邮件时使用"
            />
            <div className="min-w-0 space-y-2">
              <Label htmlFor="outlookemail_source">邮箱来源</Label>
              <Select
                id="outlookemail_source"
                value={config.outlookemail_source || "accounts"}
                onChange={(event) => setField("outlookemail_source", event.target.value)}
              >
                {OUTLOOK_SOURCES.map((item) => (
                  <option key={item.value} value={item.value}>{item.label}</option>
                ))}
              </Select>
              <p className="text-xs leading-5 text-muted-foreground">
                自动停用接口仅适用于 accounts 来源。
              </p>
            </div>
            <ConfigField {...fieldState} label="分组 ID" field="outlookemail_group_id" />
            <div className="min-w-0 space-y-2">
              <Label htmlFor="outlookemail_pick_mode">邮箱选取方式</Label>
              <Select
                id="outlookemail_pick_mode"
                value={config.outlookemail_pick_mode || "random"}
                onChange={(event) => setField("outlookemail_pick_mode", event.target.value)}
              >
                {OUTLOOK_PICK_MODES.map((item) => (
                  <option key={item.value} value={item.value}>{item.label}</option>
                ))}
              </Select>
            </div>
            <ConfigField {...fieldState} label="邮件文件夹" field="outlookemail_folder" helper="accounts 来源拉取邮件的文件夹，默认 all" />
            <ConfigField {...fieldState} label="单次拉取邮件数" field="outlookemail_top" type="number" />
            <ConfigField {...fieldState} label="临时邮箱标签 ID" field="outlookemail_temp_tag_ids" helper="仅 temp 来源使用，多个 ID 用逗号分隔" />
            <ConfigField {...fieldState}
              label="管理网页登录密码"
              field="outlookemail_web_password"
              type="password"
              helper="保存后会自动登录、获取 Session Cookie 与 CSRF Token，无需手工抓取"
            />
            <ConfigField {...fieldState}
              label="Session Cookie（兼容回退）"
              field="outlookemail_session_cookie"
              type="password"
              helper="填写管理密码后可留空；仅用于没有密码时兼容已有配置"
            />
          </CardContent>
        </Card>
        ) : null}
      </div>

      <div className="sticky bottom-[calc(4.75rem+env(safe-area-inset-bottom))] z-20 rounded-2xl border bg-card/95 p-2 shadow-lg backdrop-blur lg:hidden">
        <Button className="w-full" onClick={onSave} disabled={saving || loading}>
          <Save className="h-4 w-4" aria-hidden="true" />
          {saving ? "保存中…" : "保存全部配置"}
        </Button>
      </div>

      <Toast message={toast.message} tone={toast.tone} />
    </div>
  );
}
