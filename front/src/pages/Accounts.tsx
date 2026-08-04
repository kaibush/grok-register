import { useEffect, useMemo, useState } from "react";
import {
  Braces,
  Bug,
  Camera,
  ChevronLeft,
  ChevronRight,
  Clock3,
  Copy,
  Download,
  Eye,
  Loader2,
  LogIn,
  Mail,
  UploadCloud,
  MoreHorizontal,
  Power,
  RefreshCw,
  Search,
  X,
} from "lucide-react";
import { AccountBatchActions } from "@/components/AccountBatchActions";
import { api, type AccountRecord, type ReloginStatus } from "@/lib/api";
import { copyText, formatDuration, maskSecret } from "@/lib/utils";
import {
  Badge,
  Button,
  buttonVariants,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  EmptyState,
  Input,
  PageHeader,
  Select,
  Toast,
} from "@/components/ui";

function statusVariant(status: string) {
  if (status === "success") return "success" as const;
  if (status === "failure") return "destructive" as const;
  if (status === "cancelled") return "warning" as const;
  return "secondary" as const;
}

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    success: "成功",
    failure: "失败",
    skipped: "跳过",
    cancelled: "已停止",
  };
  return labels[status] || status || "未知";
}

function cpaVariant(status: string) {
  if (status === "success") return "success" as const;
  if (status === "failed" || status === "rejected") return "destructive" as const;
  if (status === "disabled") return "secondary" as const;
  return "warning" as const;
}

function remoteImportLabel(status: string) {
  const labels: Record<string, string> = {
    success: "已导入",
    partial: "已导入/同步失败",
    failed: "导入失败",
    ready: "待导入",
    not_configured: "未配置",
  };
  return labels[status] || status || "未配置";
}

function authStatusLabel(status: string) {
  const labels: Record<string, string> = {
    success: "成功",
    failed: "失败",
    rejected: "拒绝",
    disabled: "关闭",
    skipped: "跳过",
    not_attempted: "未执行",
  };
  return labels[status] || status || "未知";
}

function importStatusLabel(status: string) {
  const labels: Record<string, string> = {
    success: "已导入",
    partial: "同步异常",
    failed: "失败",
    ready: "待导入",
    not_configured: "未配置",
  };
  return labels[status] || status || "未知";
}

function compactBadgeVariant(status: string) {
  if (status === "success") return "success" as const;
  if (status === "failed" || status === "rejected") return "destructive" as const;
  if (status === "partial" || status === "ready" || status === "not_attempted") return "warning" as const;
  return "secondary" as const;
}

function CompactStatusBadge({ status, label }: { status: string; label: string }) {
  return (
    <Badge
      variant={compactBadgeVariant(status)}
      className="min-h-6 min-w-[58px] justify-center whitespace-nowrap rounded-md px-2 py-0 text-[11px] shadow-none"
      title={label}
    >
      {label}
    </Badge>
  );
}

function MobileStatusGrid({ item }: { item: AccountRecord }) {
  const entries = [
    ["注册", item.status, statusLabel(item.status)],
    ["Auth", item.cpa_status, authStatusLabel(item.cpa_status)],
    ["CPA", item.cpa_remote_status, importStatusLabel(item.cpa_remote_status)],
    ["G2A", item.grok2api_remote_status, importStatusLabel(item.grok2api_remote_status)],
  ];
  return (
    <div className="grid grid-cols-4 overflow-hidden rounded-lg border bg-card">
      {entries.map(([title, status, label], index) => (
        <div key={title} className={`min-w-0 px-1.5 py-1.5 text-center ${index ? "border-l" : ""}`}>
          <div className="text-[10px] leading-4 text-muted-foreground">{title}</div>
          <div className={`truncate text-[11px] font-semibold leading-4 ${
            status === "success"
              ? "text-emerald-700"
              : status === "failed" || status === "rejected"
                ? "text-red-700"
                : status === "partial" || status === "ready" || status === "not_attempted"
                  ? "text-amber-700"
                  : "text-slate-600"
          }`} title={label}>
            {label}
          </div>
        </div>
      ))}
    </div>
  );
}

function emailDisableVariant(status: string) {
  if (status === "success") return "success" as const;
  if (status === "failed") return "destructive" as const;
  if (status === "skipped_cpa" || status === "not_attempted") return "warning" as const;
  return "secondary" as const;
}

function emailDisableLabel(status: string) {
  const labels: Record<string, string> = {
    success: "已停用",
    failed: "停用失败",
    skipped_cpa: "CPA 未成功",
    feature_disabled: "功能关闭",
    unsupported_source: "非 accounts",
    not_attempted: "未执行",
    not_applicable: "不适用",
  };
  return labels[status] || status || "-";
}

function AuthExportLink({
  item,
  kind,
  variant = "ghost",
}: {
  item: AccountRecord;
  kind: "cpa" | "grok2api";
  variant?: "ghost" | "outline";
}) {
  const available = kind === "cpa" ? item.cpa_auth_available : item.grok2api_auth_available;
  const label = kind === "cpa" ? "CPA" : "Grok2API";
  if (!available) {
    return (
      <span
        className={buttonVariants({ variant, size: "sm", className: "cursor-not-allowed opacity-40" })}
        title={`${label} 文件不存在`}
        aria-disabled="true"
      >
        <Download className="h-3.5 w-3.5" aria-hidden="true" />
        {label}
      </span>
    );
  }
  return (
    <a
      href={api.accountAuthDownloadUrl(item.id, kind)}
      download
      className={buttonVariants({ variant, size: "sm" })}
      title={`导出 ${label} JSON`}
    >
      <Download className="h-3.5 w-3.5" aria-hidden="true" />
      {label}
    </a>
  );
}

function AccountDetails({
  detail,
  showPassword,
  onTogglePassword,
  onCopy,
  onCopyAuthJson,
  onDownloadAuthJson,
  authJsonLoading,
  onRelogin,
  reloginRunning,
}: {
  detail: AccountRecord;
  showPassword: boolean;
  onTogglePassword: () => void;
  onCopy: (value: string, label: string) => void;
  onCopyAuthJson: (kind: "cpa" | "grok2api") => void;
  onDownloadAuthJson: (kind: "cpa" | "grok2api") => void;
  authJsonLoading: "" | "copy-cpa" | "copy-grok2api";
  onRelogin: (item: AccountRecord) => void;
  reloginRunning: boolean;
}) {
  const fields: Array<[string, string]> = [
    ["邮箱", detail.email],
    ["密码", showPassword ? detail.password : maskSecret(detail.password)],
    ["状态", detail.status],
    ["CPA", detail.cpa_status],
    ["服务商", detail.provider],
    ["NSFW", detail.nsfw_status],
    ["账号文件", detail.account_file],
    ["Auth 路径", detail.auth_path],
    ["CPA JSON 路径", detail.cpa_auth_path],
    ["Grok2API JSON 路径", detail.grok2api_auth_path],
    ["CPA 远程入库", remoteImportLabel(detail.cpa_remote_status)],
    ["CPA 远程入库时间", detail.cpa_remote_imported_at],
    ["CPA 远程错误", detail.cpa_remote_error],
    ["Grok2API 远程入库", remoteImportLabel(detail.grok2api_remote_status)],
    ["Grok2API 远程入库时间", detail.grok2api_remote_imported_at],
    ["Grok2API 远程错误", detail.grok2api_remote_error],
    ["Auth 信息", detail.auth_info],
    ["邮箱池账号 ID", detail.email_account_id],
    ["邮箱停用状态", emailDisableLabel(detail.email_disable_status)],
    ["邮箱停用时间", detail.email_disabled_at],
    ["邮箱停用错误", detail.email_disable_error],
    ["失败截图路径", detail.screenshot_path],
    ["Batch", detail.batch_id],
    ["来源", detail.source],
  ];

  return (
    <div className="space-y-4 text-sm">
      <div className="rounded-xl border border-blue-100 bg-blue-50/70 p-3">
        <div className="break-all font-medium text-foreground">{detail.email || "未记录邮箱"}</div>
        <div className="mt-2 flex flex-wrap gap-2">
          <Badge variant={statusVariant(detail.status)}>{detail.status || "unknown"}</Badge>
          <Badge variant={cpaVariant(detail.cpa_status)}>CPA {detail.cpa_status || "-"}</Badge>
          <Badge variant={cpaVariant(detail.cpa_remote_status)}>
            CPA {remoteImportLabel(detail.cpa_remote_status)}
          </Badge>
          <Badge variant={cpaVariant(detail.grok2api_remote_status)}>
            Grok2API {remoteImportLabel(detail.grok2api_remote_status)}
          </Badge>
          <Badge variant={emailDisableVariant(detail.email_disable_status)}>
            邮箱 {emailDisableLabel(detail.email_disable_status)}
          </Badge>
        </div>
      </div>

      {detail.screenshot_url ? (
        <div className="overflow-hidden rounded-xl border border-rose-200 bg-rose-50/50">
          <div className="flex items-center gap-2 border-b border-rose-200 px-3 py-2 text-sm font-medium text-rose-800">
            <Camera className="h-4 w-4" aria-hidden="true" />
            浏览器失败现场
          </div>
          <a href={detail.screenshot_url} target="_blank" rel="noreferrer" title="在新窗口查看原图">
            <img
              src={detail.screenshot_url}
              alt={`注册失败截图 ${detail.email || detail.id}`}
              className="max-h-[28rem] w-full bg-slate-100 object-contain"
              loading="lazy"
            />
          </a>
          <div className="px-3 py-2 text-xs text-muted-foreground">点击截图可在新窗口查看原图</div>
        </div>
      ) : null}

      {detail.status === "failure" || detail.failure_reason || detail.exception_traceback ? (
        <section className="overflow-hidden rounded-xl border border-red-200 bg-red-50/60">
          <div className="flex items-center justify-between gap-3 border-b border-red-200 px-3 py-2.5">
            <div className="flex min-w-0 items-center gap-2 text-sm font-semibold text-red-800">
              <Bug className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>异常日志</span>
            </div>
            <span className="shrink-0 text-xs text-red-600">{detail.finished_at || detail.started_at || "时间未记录"}</span>
          </div>
          <div className="space-y-3 p-3">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-[7rem_minmax(0,1fr)]">
              <div className="text-xs font-medium text-red-700">异常类型</div>
              <div className="break-words text-sm text-slate-800">
                {detail.failure_type || detail.exception_type || "未分类异常"}
              </div>
              <div className="text-xs font-medium text-red-700">异常原因</div>
              <div className="whitespace-pre-wrap break-words text-sm leading-6 text-slate-800">
                {detail.failure_reason || detail.exception_type || "未记录异常原因"}
              </div>
            </div>

            {detail.exception_traceback ? (
              <details className="group overflow-hidden rounded-lg border border-red-200 bg-slate-50/90">
                <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-3 px-3 py-2 text-sm font-medium text-red-800 [&::-webkit-details-marker]:hidden">
                  <span className="min-w-0 truncate">完整异常堆栈</span>
                  <span className="shrink-0 text-xs font-normal text-red-600 group-open:hidden">展开查看</span>
                  <span className="hidden shrink-0 text-xs font-normal text-red-600 group-open:inline">收起</span>
                </summary>
                <div className="border-t border-red-200">
                  <div className="flex items-center justify-between gap-2 border-b border-slate-200 px-3 py-1.5">
                    <span className="min-w-0 truncate text-xs text-muted-foreground">
                      {detail.exception_type || "Python 异常调用栈"}
                    </span>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-8 shrink-0"
                      onClick={() => onCopy(detail.exception_traceback, "异常堆栈")}
                    >
                      <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                      复制
                    </Button>
                  </div>
                  <pre className="max-h-[48dvh] overflow-auto whitespace-pre-wrap break-words p-3 font-mono text-[11px] leading-5 text-slate-700 sm:text-xs">
                    {detail.exception_traceback}
                  </pre>
                </div>
              </details>
            ) : (
              <div className="rounded-lg border border-dashed border-red-200 bg-white/60 px-3 py-2 text-xs leading-5 text-red-700">
                该记录没有保存 Python 调用栈；新产生的注册异常会在这里显示完整堆栈。
              </div>
            )}
          </div>
        </section>
      ) : null}

      <div className="rounded-xl border border-violet-100 bg-violet-50/60 p-3">
        <div className="flex items-start gap-2">
          <Braces className="mt-0.5 h-4 w-4 shrink-0 text-violet-600" aria-hidden="true" />
          <div>
            <div className="text-sm font-medium text-foreground">授权 JSON</div>
            <p className="mt-0.5 text-xs leading-5 text-muted-foreground">
              可复制完整 JSON 内容，也可将原始 JSON 文件下载到本地。
            </p>
          </div>
        </div>
        <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
          <Button
            variant="outline"
            onClick={() => onCopyAuthJson("cpa")}
            disabled={!!authJsonLoading}
          >
            {authJsonLoading === "copy-cpa" ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <Copy className="h-4 w-4" aria-hidden="true" />
            )}
            复制 CPA JSON
          </Button>
          <Button variant="outline" onClick={() => onDownloadAuthJson("cpa")}>
            <Download className="h-4 w-4" aria-hidden="true" />
            下载 CPA JSON
          </Button>
          <Button
            variant="outline"
            onClick={() => onCopyAuthJson("grok2api")}
            disabled={!!authJsonLoading}
          >
            {authJsonLoading === "copy-grok2api" ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <Copy className="h-4 w-4" aria-hidden="true" />
            )}
            复制 Grok2API JSON
          </Button>
          <Button variant="outline" onClick={() => onDownloadAuthJson("grok2api")}>
            <Download className="h-4 w-4" aria-hidden="true" />
            下载 Grok2API JSON
          </Button>
        </div>
      </div>

      <div className="space-y-2">
        {fields.map(([label, value]) => (
          <div key={label} className="rounded-xl border bg-muted/30 p-3">
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="text-xs font-medium text-muted-foreground">{label}</span>
              <Button
                size="sm"
                variant="ghost"
                className="h-9 w-9 min-h-9 px-0"
                onClick={() => onCopy(String(value || ""), label)}
                aria-label={`复制${label}`}
              >
                <Copy className="h-3.5 w-3.5" aria-hidden="true" />
              </Button>
            </div>
            <div className="break-all whitespace-pre-wrap leading-6 text-foreground">{value || "-"}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-2">
        <Button variant="outline" onClick={onTogglePassword}>
          <Eye className="h-4 w-4" aria-hidden="true" />
          {showPassword ? "隐藏密码" : "显示密码"}
        </Button>
        <Button
          variant="secondary"
          onClick={() => onCopy(`${detail.email}----${detail.password}`, "邮箱密码")}
        >
          <Copy className="h-4 w-4" aria-hidden="true" />
          复制账号
        </Button>
        <Button
          className="col-span-2"
          variant="outline"
          onClick={() => onRelogin(detail)}
          disabled={reloginRunning || !detail.email || !detail.password}
        >
          {reloginRunning ? (
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          ) : (
            <LogIn className="h-4 w-4" aria-hidden="true" />
          )}
          {reloginRunning ? "正在重新登录" : "重新登录并刷新 SSO"}
        </Button>
      </div>
    </div>
  );
}

export function AccountsPage() {
  const [items, setItems] = useState<AccountRecord[]>([]);
  const [status, setStatus] = useState("");
  const [emailDisableStatus, setEmailDisableStatus] = useState("");
  const [keyword, setKeyword] = useState("");
  const [selected, setSelected] = useState<Record<number, boolean>>({});
  const [loading, setLoading] = useState(false);
  const [detail, setDetail] = useState<AccountRecord | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [authJsonLoading, setAuthJsonLoading] = useState<"" | "copy-cpa" | "copy-grok2api">("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [relogin, setRelogin] = useState<ReloginStatus | null>(null);
  const [reloginPolling, setReloginPolling] = useState(true);
  const [reloginFailure, setReloginFailure] = useState<{ email: string; error: string } | null>(null);
  const [batchMenuOpen, setBatchMenuOpen] = useState(false);
  const [batchBusy, setBatchBusy] = useState<"" | "export-cpa" | "export-grok2api" | "relogin">("");
  const [grok2apiImportingId, setGrok2apiImportingId] = useState<number | null>(null);
  const [moreMenu, setMoreMenu] = useState<{
    item: AccountRecord;
    top: number;
    left: number;
  } | null>(null);
  const [toast, setToast] = useState<{ message: string; tone?: "default" | "success" | "error" }>({
    message: "",
  });

  const selectedIds = useMemo(
    () => Object.entries(selected).filter(([, value]) => value).map(([key]) => Number(key)),
    [selected]
  );
  const allVisibleSelected = items.length > 0 && items.every((item) => selected[item.id]);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const pageNumbers = useMemo(() => {
    const count = Math.min(totalPages, 5);
    const start = Math.max(1, Math.min(page - 2, totalPages - count + 1));
    return Array.from({ length: count }, (_, index) => start + index);
  }, [page, totalPages]);

  const showToast = (message: string, tone: "default" | "success" | "error" = "default") => {
    setToast({ message, tone });
    window.setTimeout(() => setToast({ message: "" }), 2200);
  };

  const load = async (targetPage = page, targetPageSize = pageSize) => {
    setLoading(true);
    try {
      const data = await api.accounts({
        status,
        emailDisableStatus,
        q: keyword,
        limit: targetPageSize,
        offset: (targetPage - 1) * targetPageSize,
      });
      const responseTotal = data.total;
      const hasExactTotal = responseTotal !== null && responseTotal !== undefined
        && Number.isFinite(Number(responseTotal));
      const responseCount = Number(data.count ?? data.items?.length ?? 0);
      const offset = (targetPage - 1) * targetPageSize;
      const nextHasMore = typeof data.has_more === "boolean"
        ? data.has_more
        : responseCount >= targetPageSize;
      const nextTotal = hasExactTotal
        ? Number(responseTotal)
        : Math.max(
            total,
            offset + responseCount + (nextHasMore ? 1 : 0)
          );
      const maxPage = Math.max(1, Math.ceil(nextTotal / targetPageSize));
      if (targetPage > maxPage) {
        await load(maxPage, targetPageSize);
        return;
      }
      setItems(data.items || []);
      setTotal(nextTotal);
      setHasMore(nextHasMore);
      setPage(targetPage);
      setPageSize(targetPageSize);
      if (detail) {
        setDetail((data.items || []).find((item) => item.id === detail.id) || null);
      }
    } catch (err: any) {
      showToast(err.message || "加载失败", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load(1, 20);
  }, []);

  useEffect(() => {
    if (!reloginPolling) return;
    let active = true;
    let timer: number | undefined;
    let lastRunning = !!relogin?.running;
    const check = async () => {
      try {
        const result = await api.reloginStatus();
        if (!active) return;
        const next = result.relogin;
        setRelogin(next);
        if (!next.running) {
          if (lastRunning) await load();
          if (next.error) {
            setReloginFailure({
              email: next.total_count > 1 ? "" : next.email,
              error: next.error,
            });
          } else if (lastRunning) {
            showToast("重新登录完成，授权文件已刷新", "success");
          }
          setReloginPolling(false);
          return;
        }
        lastRunning = next.running;
        if (next.running) timer = window.setTimeout(check, 2000);
        else setReloginPolling(false);
      } catch {
        if (active) timer = window.setTimeout(check, 5000);
      }
    };
    void check();
    return () => {
      active = false;
      if (timer) window.clearTimeout(timer);
    };
  }, [reloginPolling]);

  useEffect(() => {
    if (!detail) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setDetail(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [detail]);

  useEffect(() => {
    if (!moreMenu) return;
    const close = () => setMoreMenu(null);
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    return () => {
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
    };
  }, [moreMenu]);

  const toggleAll = (checked: boolean) => {
    setSelected((previous) => {
      const next = { ...previous };
      for (const item of items) {
        if (checked) next[item.id] = true;
        else delete next[item.id];
      }
      return next;
    });
  };

  const onCopy = async (value: string, label: string) => {
    const ok = await copyText(value);
    showToast(ok ? `已复制${label}` : "复制失败", ok ? "success" : "error");
  };

  const onCopyAuthJson = async (kind: "cpa" | "grok2api") => {
    if (!detail) return;
    setAuthJsonLoading(`copy-${kind}` as "copy-cpa" | "copy-grok2api");
    try {
      const result = await api.accountAuthJson(detail.id, kind);
      const ok = await copyText(result.content);
      const label = kind === "cpa" ? "CPA JSON" : "Grok2API JSON";
      showToast(ok ? `已复制${label}` : `${label}复制失败`, ok ? "success" : "error");
    } catch (err: any) {
      showToast(err.message || "读取授权 JSON 失败", "error");
    } finally {
      setAuthJsonLoading("");
    }
  };

  const startAuthDownload = (accountId: number, kind: "cpa" | "grok2api") => {
    const link = document.createElement("a");
    link.href = api.accountAuthDownloadUrl(accountId, kind);
    link.download = "";
    document.body.appendChild(link);
    link.click();
    link.remove();
    showToast(`已提交${kind === "cpa" ? "CPA" : "Grok2API"}导出`, "success");
  };

  const onDownloadAuthJson = (kind: "cpa" | "grok2api") => {
    if (!detail) return;
    const available = kind === "cpa" ? detail.cpa_auth_available : detail.grok2api_auth_available;
    if (!available) {
      showToast(`${kind === "cpa" ? "CPA" : "Grok2API"} 文件不存在`, "error");
      return;
    }
    startAuthDownload(detail.id, kind);
  };

  const onBatchExport = async (kind: "cpa" | "grok2api") => {
    if (!selectedIds.length) return;
    setBatchMenuOpen(false);
    setBatchBusy(`export-${kind}` as "export-cpa" | "export-grok2api");
    try {
      const result = await api.downloadAuthArchive(selectedIds, kind);
      const url = URL.createObjectURL(result.blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = result.filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      const skipped = result.skipped ? `，跳过 ${result.skipped} 个无文件账号` : "";
      showToast(`已导出 ${result.exported} 个授权文件${skipped}`, "success");
    } catch (err: any) {
      showToast(err.message || "批量导出失败", "error");
    } finally {
      setBatchBusy("");
    }
  };

  const onBatchRelogin = async () => {
    if (!selectedIds.length) return;
    if (!window.confirm(`按顺序重新登录选中的 ${selectedIds.length} 个账号并刷新授权文件？`)) return;
    setBatchMenuOpen(false);
    setBatchBusy("relogin");
    try {
      const result = await api.startBatchRelogin(selectedIds);
      setRelogin(result.relogin);
      setReloginFailure(null);
      setReloginPolling(!!result.relogin.running);
      showToast("已启动批量重新登录", "success");
    } catch (err: any) {
      showToast(err.message || "启动批量重新登录失败", "error");
    } finally {
      setBatchBusy("");
    }
  };

  const onDelete = async () => {
    if (!selectedIds.length) {
      showToast("请先选择记录", "error");
      return;
    }
    if (!window.confirm(`删除 ${selectedIds.length} 条记录及其关联文件？此操作不可恢复。`)) return;
    try {
      const result = await api.deleteAccounts(selectedIds, true);
      showToast(`已删除 ${result.deleted} 条，文件 ${result.deleted_files} 个`, "success");
      setSelected({});
      setBatchMenuOpen(false);
      setDetail(null);
      await load(page, pageSize);
    } catch (err: any) {
      showToast(err.message || "删除失败", "error");
    }
  };

  const onRelogin = async (item: AccountRecord) => {
    if (!item.email || !item.password) {
      showToast("该记录缺少邮箱或密码", "error");
      return;
    }
    if (!window.confirm(`使用已保存的账号密码重新登录 ${item.email}，刷新 SSO 和授权文件？`)) return;
    try {
      const result = await api.startRelogin(item.id);
      setRelogin(result.relogin);
      setReloginFailure(null);
      setReloginPolling(!!result.relogin.running);
      showToast("已启动重新登录，请稍候", "success");
    } catch (err: any) {
      showToast(err.message || "启动重新登录失败", "error");
    }
  };

  const onImportGrok2API = async (item: AccountRecord) => {
    setGrok2apiImportingId(item.id);
    try {
      const response = await api.importAccountToGrok2API(item.id);
      setItems((previous) => previous.map((value) => value.id === item.id ? response.item : value));
      if (detail?.id === item.id) setDetail(response.item);
      const result = response.result || {};
      const syncFailed = result.syncFailed || 0;
      showToast(
        syncFailed
          ? `Grok2API 已入库，但远程同步失败 ${syncFailed} 个`
          : `Grok2API 导入完成：新增 ${result.created || 0}，更新 ${result.updated || 0}`,
        syncFailed ? "error" : "success"
      );
    } catch (err: any) {
      showToast(err.message || "Grok2API 导入失败", "error");
      await load();
    } finally {
      setGrok2apiImportingId(null);
    }
  };

  const openMoreMenu = (item: AccountRecord, button: HTMLButtonElement) => {
    const rect = button.getBoundingClientRect();
    const menuWidth = 224;
    const menuHeight = item.grok2api_remote_configured ? 220 : 172;
    const left = Math.min(Math.max(rect.right - menuWidth, 8), window.innerWidth - menuWidth - 8);
    const top = rect.bottom + menuHeight > window.innerHeight
      ? Math.max(8, rect.top - menuHeight - 6)
      : rect.bottom + 6;
    setMoreMenu({ item, top, left });
  };

  const MoreButton = ({ item, className = "" }: { item: AccountRecord; className?: string }) => (
    <Button
      size="sm"
      variant="outline"
      className={className}
      onClick={(event) => openMoreMenu(item, event.currentTarget)}
      aria-haspopup="menu"
      aria-expanded={moreMenu?.item.id === item.id}
    >
      <MoreHorizontal className="h-4 w-4" aria-hidden="true" />
      更多
    </Button>
  );

  const MoreMenuContent = ({ item }: { item: AccountRecord }) => {
    const currentRelogin = !!relogin?.running && relogin.account_id === item.id;
    const importing = grok2apiImportingId === item.id;
    const exportEntry = (kind: "cpa" | "grok2api") => {
      const available = kind === "cpa" ? item.cpa_auth_available : item.grok2api_auth_available;
      const label = kind === "cpa" ? "下载 CPA JSON" : "下载 Grok2API JSON";
      const content = (
        <>
          <Download className="h-4 w-4" aria-hidden="true" />
          {label}
        </>
      );
      if (!available) {
        return (
          <span
            className="flex min-h-10 cursor-not-allowed items-center gap-2 rounded-lg px-3 text-sm text-muted-foreground opacity-45"
            title={`${label} 文件不存在`}
          >
            {content}
          </span>
        );
      }
      return (
        <a
          href={api.accountAuthDownloadUrl(item.id, kind)}
          download
          className="flex min-h-10 items-center gap-2 rounded-lg px-3 text-sm font-medium hover:bg-muted"
          onClick={() => setMoreMenu(null)}
        >
          {content}
        </a>
      );
    };
    return (
      <div role="menu" className="space-y-1">
        {exportEntry("cpa")}
        {exportEntry("grok2api")}
        {item.grok2api_remote_configured ? (
          <button
            type="button"
            role="menuitem"
            className="flex min-h-10 w-full items-center gap-2 rounded-lg px-3 text-left text-sm font-medium hover:bg-muted disabled:cursor-not-allowed disabled:opacity-45"
            disabled={importing || !item.grok2api_auth_available}
            title={!item.grok2api_auth_available ? "Grok2API JSON 文件不存在" : undefined}
            onClick={() => {
              setMoreMenu(null);
              void onImportGrok2API(item);
            }}
          >
            {importing ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <UploadCloud className="h-4 w-4" aria-hidden="true" />
            )}
            {importing ? "正在导入 Grok2API" : "导入到 Grok2API"}
          </button>
        ) : null}
        <div className="my-1 border-t" />
        <button
          type="button"
          role="menuitem"
          className="flex min-h-10 w-full items-center gap-2 rounded-lg px-3 text-left text-sm font-medium hover:bg-muted disabled:cursor-not-allowed disabled:opacity-45"
          disabled={!!relogin?.running || !item.email || !item.password}
          onClick={() => {
            setMoreMenu(null);
            void onRelogin(item);
          }}
        >
          {currentRelogin ? (
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          ) : (
            <LogIn className="h-4 w-4" aria-hidden="true" />
          )}
          {currentRelogin ? relogin?.stage || "重新登录中" : "重新登录并刷新 SSO"}
        </button>
      </div>
    );
  };

  return (
    <div className="space-y-5 sm:space-y-6">
      <PageHeader
        title="账号管理"
        description="筛选和查看注册结果，在手机端使用卡片列表，在大屏设备上使用数据表格。"
        actions={
          <>
            <Button variant="outline" onClick={() => void load(page, pageSize)} disabled={loading}>
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} aria-hidden="true" />
              刷新
            </Button>
            <AccountBatchActions
              selectedCount={selectedIds.length}
              busy={!!batchBusy}
              menuOpen={batchMenuOpen}
              reloginRunning={!!relogin?.running}
              onToggleMenu={() => setBatchMenuOpen((open) => !open)}
              onCloseMenu={() => setBatchMenuOpen(false)}
              onExport={(kind) => void onBatchExport(kind)}
              onRelogin={() => void onBatchRelogin()}
              onDelete={() => {
                setBatchMenuOpen(false);
                void onDelete();
              }}
            />
          </>
        }
      />

      {relogin?.running ? (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-900">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          <span className="font-medium">
            {relogin.total_count > 1
              ? `批量重新登录 ${Math.min(relogin.completed_count + 1, relogin.total_count)}/${relogin.total_count}`
              : `正在重新登录 ${relogin.email}`}
          </span>
          {relogin.total_count > 1 ? <span className="text-blue-700">{relogin.email}</span> : null}
          <span className="text-blue-700">{relogin.stage}</span>
        </div>
      ) : null}

      {reloginFailure ? (
        <div role="alert" className="flex items-start justify-between gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-900">
          <div className="min-w-0">
            <div className="font-medium">重新登录失败</div>
            <div className="mt-1 break-all text-red-700">
              {reloginFailure.email ? `${reloginFailure.email}：` : ""}{reloginFailure.error}
            </div>
          </div>
          <Button size="icon" variant="ghost" className="shrink-0" onClick={() => setReloginFailure(null)} aria-label="关闭重新登录失败提醒">
            <X className="h-4 w-4" aria-hidden="true" />
          </Button>
        </div>
      ) : null}

      <Card>
        <CardContent className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-[160px_190px_minmax(0,1fr)_auto]">
          <Select
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setSelected({});
            }}
            aria-label="按状态筛选"
          >
            <option value="">全部状态</option>
            <option value="success">success</option>
            <option value="failure">failure</option>
            <option value="skipped">skipped</option>
            <option value="cancelled">cancelled</option>
          </Select>
          <Select
            value={emailDisableStatus}
            onChange={(e) => {
              setEmailDisableStatus(e.target.value);
              setSelected({});
            }}
            aria-label="按邮箱停用状态筛选"
          >
            <option value="">全部停用状态</option>
            <option value="success">已停用</option>
            <option value="failed">停用失败</option>
            <option value="skipped_cpa">CPA 未成功</option>
            <option value="feature_disabled">功能关闭</option>
            <option value="unsupported_source">非 accounts</option>
            <option value="not_attempted">未执行</option>
            <option value="not_applicable">不适用</option>
          </Select>
          <div className="relative min-w-0 sm:col-span-2 lg:col-span-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              className="pl-9"
              type="search"
              placeholder="搜索邮箱、服务商、失败原因或 Batch"
              value={keyword}
              onChange={(e) => {
                setKeyword(e.target.value);
                setSelected({});
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  setSelected({});
                  void load(1, pageSize);
                }
              }}
              aria-label="搜索账号记录"
            />
          </div>
          <Button
            className="sm:col-span-2 lg:col-span-1"
            onClick={() => {
              setSelected({});
              void load(1, pageSize);
            }}
            disabled={loading}
          >
            <Search className="h-4 w-4" aria-hidden="true" />
            查询
          </Button>
        </CardContent>
      </Card>

      <div>
        <Card className="min-w-0 overflow-hidden">
          <CardHeader className="flex-row items-center justify-between gap-3">
            <div>
              <CardTitle>注册记录</CardTitle>
              <CardDescription>
                共 {total} 条，第 {page} / {totalPages} 页
                {selectedIds.length ? `，已选 ${selectedIds.length} 条` : ""}。
              </CardDescription>
            </div>
            <label className="flex min-h-11 cursor-pointer items-center gap-2 rounded-xl px-2 text-sm text-muted-foreground hover:bg-muted xl:hidden">
              <input
                type="checkbox"
                checked={allVisibleSelected}
                onChange={(e) => toggleAll(e.target.checked)}
              />
              全选本页
            </label>
          </CardHeader>
          <CardContent className="p-0">
            {items.length === 0 ? (
              <div className="p-4 sm:p-6">
                <EmptyState title="暂无账号记录" description="启动注册后，成功或失败结果会显示在这里。" />
              </div>
            ) : (
              <>
                <div className="divide-y xl:hidden">
                  {items.map((item) => (
                    <article key={item.id} className="space-y-3 p-4">
                      <div className="flex items-start gap-3">
                        <label className="flex h-11 w-8 shrink-0 cursor-pointer items-center justify-center" aria-label={`选择 ${item.email}`}>
                          <input
                            type="checkbox"
                            checked={!!selected[item.id]}
                            onChange={(e) =>
                              setSelected((prev) => ({ ...prev, [item.id]: e.target.checked }))
                            }
                          />
                        </label>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-start gap-2">
                            <Mail className="mt-1 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
                            <div className="break-all font-medium leading-6 text-foreground">{item.email || "-"}</div>
                          </div>
                          <div className="mt-2 space-y-2">
                            <MobileStatusGrid item={item} />
                            <div className="flex justify-end">
                              <Badge variant={emailDisableVariant(item.email_disable_status)}>
                                <Power className="mr-1 h-3 w-3" aria-hidden="true" />
                                邮箱 {emailDisableLabel(item.email_disable_status)}
                              </Badge>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-2 rounded-xl bg-muted/40 p-3 text-xs leading-5 text-muted-foreground">
                        <div>
                          <span className="block">服务商</span>
                          <strong className="block truncate font-medium text-foreground">{item.provider || "-"}</strong>
                        </div>
                        <div>
                          <span className="block">耗时</span>
                          <strong className="block font-medium text-foreground">{formatDuration(item.duration_seconds)}</strong>
                        </div>
                        <div className="col-span-2 flex items-start gap-1.5 border-t pt-2">
                          <Clock3 className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                          <span className="break-all">{item.finished_at || "未记录完成时间"}</span>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-2">
                        <Button variant="outline" onClick={() => setDetail(item)}>
                          查看
                          <ChevronRight className="h-4 w-4" aria-hidden="true" />
                        </Button>
                        <MoreButton item={item} className="w-full" />
                      </div>
                    </article>
                  ))}
                </div>

                <div className="hidden max-h-[720px] overflow-auto bg-slate-50/70 p-2 xl:block">
                  <table className="w-full min-w-[1040px] border-separate text-left text-sm [border-spacing:0_6px]">
                    <thead className="sticky top-0 z-10 bg-slate-50/95 backdrop-blur">
                      <tr className="text-xs font-medium text-muted-foreground">
                        <th className="w-12 px-4 py-2">
                          <input
                            type="checkbox"
                            checked={allVisibleSelected}
                            onChange={(e) => toggleAll(e.target.checked)}
                            aria-label="全选当前记录"
                          />
                        </th>
                        <th className="px-3 py-2">账号</th>
                        <th className="w-[82px] px-2 py-2 text-center">注册</th>
                        <th className="w-[82px] px-2 py-2 text-center">Auth</th>
                        <th className="w-[92px] px-2 py-2 text-center">CPA 入库</th>
                        <th className="w-[104px] px-2 py-2 text-center">Grok2API</th>
                        <th className="w-[98px] px-2 py-2 text-center">邮箱状态</th>
                        <th className="px-3 py-2">服务商</th>
                        <th className="px-3 py-2">耗时</th>
                        <th className="sticky right-0 z-20 w-[170px] bg-slate-50/95 px-3 py-2 text-center backdrop-blur">操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      {items.map((item) => (
                        <tr
                          key={item.id}
                          className="group"
                        >
                          <td className={`rounded-l-xl border-y border-l px-4 py-2.5 transition-colors ${detail?.id === item.id ? "border-blue-200 bg-blue-50" : "bg-card group-hover:bg-blue-50/60"}`}>
                            <input
                              type="checkbox"
                              checked={!!selected[item.id]}
                              onChange={(e) =>
                                setSelected((prev) => ({ ...prev, [item.id]: e.target.checked }))
                              }
                              aria-label={`选择 ${item.email}`}
                            />
                          </td>
                          <td className={`max-w-[270px] border-y px-3 py-2.5 transition-colors ${detail?.id === item.id ? "border-blue-200 bg-blue-50" : "bg-card group-hover:bg-blue-50/60"}`}>
                            <div className="flex min-w-0 items-center gap-2.5">
                              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-50 text-primary ring-1 ring-blue-100">
                                <Mail className="h-4 w-4" aria-hidden="true" />
                              </span>
                              <div className="min-w-0">
                                <div className="truncate font-medium text-foreground" title={item.email}>{item.email || "-"}</div>
                                <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{item.finished_at || "未记录时间"}</div>
                              </div>
                            </div>
                          </td>
                          <td className={`border-y px-2 py-2.5 text-center transition-colors ${detail?.id === item.id ? "border-blue-200 bg-blue-50" : "bg-card group-hover:bg-blue-50/60"}`}>
                            <CompactStatusBadge status={item.status} label={statusLabel(item.status)} />
                          </td>
                          <td className={`border-y px-2 py-2.5 text-center transition-colors ${detail?.id === item.id ? "border-blue-200 bg-blue-50" : "bg-card group-hover:bg-blue-50/60"}`}>
                            <CompactStatusBadge status={item.cpa_status} label={authStatusLabel(item.cpa_status)} />
                          </td>
                          <td className={`border-y px-2 py-2.5 text-center transition-colors ${detail?.id === item.id ? "border-blue-200 bg-blue-50" : "bg-card group-hover:bg-blue-50/60"}`}>
                            <CompactStatusBadge
                              status={item.cpa_remote_status}
                              label={importStatusLabel(item.cpa_remote_status)}
                            />
                          </td>
                          <td className={`border-y px-2 py-2.5 text-center transition-colors ${detail?.id === item.id ? "border-blue-200 bg-blue-50" : "bg-card group-hover:bg-blue-50/60"}`}>
                            <CompactStatusBadge
                              status={item.grok2api_remote_status}
                              label={importStatusLabel(item.grok2api_remote_status)}
                            />
                          </td>
                          <td className={`border-y px-2 py-2.5 text-center transition-colors ${detail?.id === item.id ? "border-blue-200 bg-blue-50" : "bg-card group-hover:bg-blue-50/60"}`}>
                            <Badge
                              variant={emailDisableVariant(item.email_disable_status)}
                              className="min-h-6 min-w-[62px] justify-center whitespace-nowrap rounded-md px-2 py-0 text-[11px] shadow-none"
                            >
                              {emailDisableLabel(item.email_disable_status)}
                            </Badge>
                            {item.email_disable_error ? (
                              <div
                                className="mt-1 max-w-[90px] truncate text-[10px] text-red-600"
                                title={item.email_disable_error}
                              >
                                {item.email_disable_error}
                              </div>
                            ) : null}
                          </td>
                          <td className={`border-y px-3 py-2.5 text-muted-foreground transition-colors ${detail?.id === item.id ? "border-blue-200 bg-blue-50" : "bg-card group-hover:bg-blue-50/60"}`}>
                            <span className="inline-flex rounded-md bg-slate-100 px-2 py-1 text-xs font-medium text-slate-600">{item.provider || "-"}</span>
                          </td>
                          <td className={`border-y px-3 py-2.5 tabular-nums text-muted-foreground transition-colors ${detail?.id === item.id ? "border-blue-200 bg-blue-50" : "bg-card group-hover:bg-blue-50/60"}`}>{formatDuration(item.duration_seconds)}</td>
                          <td className={`sticky right-0 z-[5] rounded-r-xl border-y border-r px-3 py-2.5 shadow-[-10px_0_18px_-18px_rgba(15,23,42,0.45)] transition-colors ${detail?.id === item.id ? "border-blue-200 bg-blue-50" : "bg-card group-hover:bg-blue-50/60"}`}>
                            <div className="flex items-center justify-center gap-1.5">
                              <Button size="sm" variant="outline" onClick={() => setDetail(item)}>
                                查看
                              </Button>
                              <MoreButton item={item} />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="flex flex-col gap-3 border-t px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span>每页</span>
                    <Select
                      className="h-9 min-h-9 w-20 py-1"
                      value={String(pageSize)}
                      onChange={(event) => void load(1, Number(event.target.value))}
                      aria-label="每页记录数"
                    >
                      <option value="20">20</option>
                      <option value="50">50</option>
                      <option value="100">100</option>
                    </Select>
                    <span>条，共 {total} 条</span>
                  </div>
                  <div className="flex items-center justify-between gap-2 sm:justify-end">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={loading || page <= 1}
                      onClick={() => void load(page - 1, pageSize)}
                    >
                      <ChevronLeft className="h-4 w-4" aria-hidden="true" />
                      上一页
                    </Button>
                    <span className="min-w-16 text-center text-xs font-medium text-muted-foreground sm:hidden">
                      {page} / {totalPages}
                    </span>
                    <div className="hidden items-center gap-1 sm:flex" aria-label="页码">
                      {pageNumbers.map((pageNumber) => (
                        <Button
                          key={pageNumber}
                          size="sm"
                          variant={pageNumber === page ? "default" : "outline"}
                          className="h-9 min-h-9 w-9 px-0"
                          disabled={loading}
                          onClick={() => void load(pageNumber, pageSize)}
                          aria-current={pageNumber === page ? "page" : undefined}
                        >
                          {pageNumber}
                        </Button>
                      ))}
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={loading || !hasMore}
                      onClick={() => void load(page + 1, pageSize)}
                    >
                      下一页
                      <ChevronRight className="h-4 w-4" aria-hidden="true" />
                    </Button>
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>

      </div>

      {moreMenu ? (
        <>
          <button
            type="button"
            className="fixed inset-0 z-[75] hidden cursor-default bg-transparent xl:block"
            onClick={() => setMoreMenu(null)}
            aria-label="关闭更多操作"
          />
          <div
            className="fixed z-[76] hidden w-56 rounded-xl border bg-card p-2 shadow-2xl xl:block"
            style={{ top: moreMenu.top, left: moreMenu.left }}
          >
            <MoreMenuContent item={moreMenu.item} />
          </div>
          <div
            className="fixed inset-0 z-[75] flex items-end bg-slate-950/45 xl:hidden"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget) setMoreMenu(null);
            }}
          >
            <section className="w-full rounded-t-3xl bg-card px-4 pb-[calc(1rem+env(safe-area-inset-bottom))] pt-3 shadow-2xl">
              <div className="mx-auto mb-3 h-1.5 w-12 rounded-full bg-slate-300" />
              <div className="mb-2 flex items-center justify-between gap-3 px-1">
                <div className="min-w-0">
                  <div className="font-medium">更多操作</div>
                  <div className="truncate text-xs text-muted-foreground">{moreMenu.item.email}</div>
                </div>
                <Button size="icon" variant="ghost" onClick={() => setMoreMenu(null)} aria-label="关闭更多操作">
                  <X className="h-5 w-5" aria-hidden="true" />
                </Button>
              </div>
              <MoreMenuContent item={moreMenu.item} />
            </section>
          </div>
        </>
      ) : null}

      {detail ? (
        <div
          className="fixed inset-0 z-[70] flex items-end bg-slate-950/50 sm:items-center sm:justify-center sm:p-6"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setDetail(null);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="account-detail-title"
            className="max-h-[92dvh] w-full overflow-hidden rounded-t-3xl bg-card shadow-2xl sm:max-w-4xl sm:rounded-3xl"
          >
            <div className="mx-auto mt-2 h-1.5 w-12 rounded-full bg-slate-300" />
            <header className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b bg-card px-4 py-3">
              <div className="min-w-0">
                <h2 id="account-detail-title" className="font-semibold text-foreground">账号详情</h2>
                <p className="truncate text-xs text-muted-foreground">{detail.email || "未记录邮箱"}</p>
              </div>
              <Button size="icon" variant="ghost" onClick={() => setDetail(null)} aria-label="关闭账号详情">
                <X className="h-5 w-5" aria-hidden="true" />
              </Button>
            </header>
            <div className="max-h-[calc(92dvh-74px)] overflow-y-auto px-4 pb-[calc(1.5rem+env(safe-area-inset-bottom))] pt-4">
              <AccountDetails
                detail={detail}
                showPassword={showPassword}
                onTogglePassword={() => setShowPassword((value) => !value)}
                onCopy={onCopy}
                onCopyAuthJson={onCopyAuthJson}
                onDownloadAuthJson={onDownloadAuthJson}
                authJsonLoading={authJsonLoading}
                onRelogin={onRelogin}
                reloginRunning={!!relogin?.running && relogin.account_id === detail.id}
              />
            </div>
          </section>
        </div>
      ) : null}

      <Toast message={toast.message} tone={toast.tone} />
    </div>
  );
}
