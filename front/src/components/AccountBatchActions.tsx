import { Archive, ChevronDown, ListChecks, Loader2, LogIn, Trash2 } from "lucide-react";
import { Button } from "@/components/ui";

export function AccountBatchActions({
  selectedCount,
  busy,
  menuOpen,
  reloginRunning,
  onToggleMenu,
  onCloseMenu,
  onExport,
  onRelogin,
  onDelete,
}: {
  selectedCount: number;
  busy: boolean;
  menuOpen: boolean;
  reloginRunning: boolean;
  onToggleMenu: () => void;
  onCloseMenu: () => void;
  onExport: (kind: "cpa" | "grok2api") => void;
  onRelogin: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="relative">
      <Button
        variant="outline"
        className="w-full"
        onClick={onToggleMenu}
        disabled={!selectedCount || busy}
        aria-haspopup="menu"
        aria-expanded={menuOpen}
      >
        {busy ? (
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
        ) : (
          <ListChecks className="h-4 w-4" aria-hidden="true" />
        )}
        批量操作 ({selectedCount})
        <ChevronDown className="h-4 w-4" aria-hidden="true" />
      </Button>
      {menuOpen ? (
        <>
          <button
            type="button"
            className="fixed inset-0 z-30 cursor-default"
            onClick={onCloseMenu}
            aria-label="关闭批量操作"
          />
          <div
            role="menu"
            className="absolute right-0 top-[calc(100%+0.5rem)] z-40 w-64 rounded-lg border bg-card p-2 shadow-2xl"
          >
            <button
              type="button"
              role="menuitem"
              className="flex min-h-10 w-full items-center gap-2 rounded-lg px-3 text-left text-sm font-medium hover:bg-muted"
              onClick={() => onExport("cpa")}
            >
              <Archive className="h-4 w-4" aria-hidden="true" />
              导出 CPA JSON 压缩包
            </button>
            <button
              type="button"
              role="menuitem"
              className="flex min-h-10 w-full items-center gap-2 rounded-lg px-3 text-left text-sm font-medium hover:bg-muted"
              onClick={() => onExport("grok2api")}
            >
              <Archive className="h-4 w-4" aria-hidden="true" />
              导出 Grok2API JSON 压缩包
            </button>
            <button
              type="button"
              role="menuitem"
              className="flex min-h-10 w-full items-center gap-2 rounded-lg px-3 text-left text-sm font-medium hover:bg-muted disabled:cursor-not-allowed disabled:opacity-45"
              disabled={reloginRunning}
              onClick={onRelogin}
            >
              <LogIn className="h-4 w-4" aria-hidden="true" />
              重新登录并刷新 SSO
            </button>
            <div className="my-1 border-t" />
            <button
              type="button"
              role="menuitem"
              className="flex min-h-10 w-full items-center gap-2 rounded-lg px-3 text-left text-sm font-medium text-destructive hover:bg-red-50"
              onClick={onDelete}
            >
              <Trash2 className="h-4 w-4" aria-hidden="true" />
              删除选中账号
            </button>
          </div>
        </>
      ) : null}
    </div>
  );
}
