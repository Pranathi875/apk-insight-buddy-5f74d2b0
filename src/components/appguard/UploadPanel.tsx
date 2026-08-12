import { useCallback, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { Upload, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { analyzeApk, ApkValidationError, MAX_APK_BYTES, type ProgressStage } from "@/lib/analysis/analyze";
import { saveAnalysis } from "@/lib/appguard/store";
import { formatBytes } from "@/lib/appguard/format";

const STAGE_LABEL: Record<ProgressStage, string> = {
  hashing: "Hashing package",
  container: "Reading APK container",
  manifest: "Decoding AndroidManifest.xml",
  dex: "Scanning DEX bytecode",
  capabilities: "Detecting capabilities",
  rules: "Evaluating rules and scoring",
  done: "Finalizing",
};

export function UploadPanel({ onSaved }: { onSaved?: () => void }) {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<ProgressStage>("hashing");
  const [percent, setPercent] = useState(0);
  const [currentFile, setCurrentFile] = useState<string | null>(null);

  const run = useCallback(
    async (file: File) => {
      if (busy) return;
      setBusy(true);
      setCurrentFile(`${file.name} · ${formatBytes(file.size)}`);
      setPercent(2);
      setStage("hashing");

      try {
        if (file.size > MAX_APK_BYTES) {
          throw new ApkValidationError(
            `This file is ${formatBytes(file.size)}. The browser analyzer accepts up to ${formatBytes(MAX_APK_BYTES)}.`,
          );
        }
        const bytes = new Uint8Array(await file.arrayBuffer());
        const result = await analyzeApk(bytes, {
          fileName: file.name,
          onProgress: (nextStage, nextPercent) => {
            setStage(nextStage);
            setPercent(nextPercent);
          },
        });
        const id = await saveAnalysis(result);
        onSaved?.();
        toast.success("Analysis complete", {
          description: `${result.manifest.packageName ?? file.name} · ${result.findings.length} findings`,
        });
        navigate({ to: "/analysis/$id", params: { id } });
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unknown error";
        toast.error(
          error instanceof ApkValidationError ? "That file could not be analyzed" : "Analysis failed",
          { description: message },
        );
      } finally {
        setBusy(false);
        setPercent(0);
        setCurrentFile(null);
      }
    },
    [busy, navigate, onSaved],
  );

  return (
    <div
      onDragOver={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(event) => {
        event.preventDefault();
        setDragging(false);
        const file = event.dataTransfer.files?.[0];
        if (file) void run(file);
      }}
      className={`rounded-xl border border-dashed p-8 text-center transition-colors ${
        dragging ? "border-primary bg-primary/5" : "border-border bg-card/60"
      }`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".apk,.apks,application/vnd.android.package-archive"
        className="hidden"
        onChange={(event) => {
          const file = event.target.files?.[0];
          event.target.value = "";
          if (file) void run(file);
        }}
      />

      {busy ? (
        <div className="mx-auto max-w-md space-y-3">
          <Loader2 className="mx-auto size-6 animate-spin text-primary" />
          <p className="font-display text-sm font-semibold">{STAGE_LABEL[stage]}</p>
          <Progress value={percent} className="h-1.5" />
          <p className="font-mono text-xs text-muted-foreground">{currentFile}</p>
        </div>
      ) : (
        <div className="mx-auto max-w-md space-y-3">
          <span className="mx-auto flex size-11 items-center justify-center rounded-lg border border-border bg-secondary text-primary">
            <Upload className="size-5" />
          </span>
          <h2 className="font-display text-lg font-semibold">Drop an APK to analyze</h2>
          <p className="text-sm text-muted-foreground">
            The package is decoded locally in your browser: container layout, binary manifest, DEX
            bytecode and signing artifacts. Only the derived report is stored.
          </p>
          <Button onClick={() => inputRef.current?.click()} size="lg">
            Select APK file
          </Button>
          <p className="font-mono text-[11px] text-muted-foreground">
            .apk · up to {formatBytes(MAX_APK_BYTES)}
          </p>
        </div>
      )}
    </div>
  );
}