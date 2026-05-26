// Wails IPC + runtime 类型声明
//
// **策略**：strong-type 用得最多的 ~30 个 method，其它走 `[key: string]: any`
// 兜底（不会 compile error）。100+ 个 IPC method 一次全列工作量太大、易过时。
// 渐进迁移：未来谁碰到哪个 method 就给它加精确签名。
//
// 真正"权威"的 TS bindings 应当来自 `wails generate ts` —— 但那要求 wails 正常
// 跑 wails dev / build 生成；本文件是手写的精简补丁，足够 IDE 自动完成 + 编译期
// catch IPC 名字打错（v2.4.0 audit 时发现的真实 bug）。

declare global {
  interface Window {
    runtime?: {
      EventsOn: (event: string, callback: (data: any) => void) => () => void;
      EventsEmit: (event: string, ...args: any[]) => void;
      WindowReload?: () => void;
      Quit?: () => void;
    };
    // v2.8.47 后端 package main → package appcore，wails 生成的命名空间
    // 也从 main 改成 appcore。这里两个都列出来 —— 老的 main 在升级期
    // 还有用户安装的版本会用到 (兼容前端代码 `?? main.App` 兜底)。
    go?: {
      appcore?: {
        App?: WailsApp;
      };
      main?: {
        App?: WailsApp;
      };
    };
  }
}

// v2.8.52: Wails generate 的模块 (wailsjs/go/{appcore,main}/App, wailsjs/runtime/runtime)
// 在源代码不存在 (gitignored, build 时才生成)。tsc 找不到。
// TS 的 `declare module` 不支持相对路径 shim，所以走 import.ts 那两行 `@ts-ignore` 兜底。
// 这里只放纯 ambient 类型声明（不涉及模块路径）。

// =============================================================================
// 业务数据类型（与 Go 端 struct 对应；保持手动同步）
// =============================================================================

export interface DriveInfo {
  path: string;
  label?: string;
  size?: number;
  fsType?: string;
  isPhysical?: boolean;
  isRemovable?: boolean;
  // 其他字段在用到时再加
  [key: string]: unknown;
}

export interface RecoveredFile {
  id: string;
  fileName: string;
  size: number;
  category?: string;
  extension?: string;
  offset?: number;
  source?: string;
  isValid?: boolean;
  confidence?: number;
  validationMsg?: string;
  sha256?: string;
  [key: string]: unknown;
}

export interface ScanProgress {
  phase: string;
  percent: number;
  bytesScanned: number;
  totalBytes: number;
  filesFound: number;
  currentFile: string;
  speed: number;
  eta: string;
  elapsed: string;
  [key: string]: unknown;
}

export interface RecoveryProgress {
  current: number;
  total: number;
  currentFile?: string;
  bytesWritten?: number;
  success?: number;
  partial?: number;
  failed?: number;
  [key: string]: unknown;
}

export interface FileRecoveryRecord {
  fileId: string;
  fileName: string;
  category?: string;
  size?: number;
  sizeHuman?: string;
  state: "success" | "partial" | "failed" | "skipped" | string;
  outputPath?: string;
  message?: string;
  durationMs?: number;
  completedAt?: string;
}

export interface UpdateCheckResult {
  hasUpdate: boolean;
  currentVersion: string;
  latestVersion: string;
  downloadPage?: string;
  releaseNotes?: string;
  assets?: Array<{ name: string; size: number; downloadURL: string }>;
}

export interface IOSBackupInfo {
  path: string;
  deviceName?: string;
  iosVersion?: string;
  encrypted: boolean;
}

export interface AndroidBackupInfo {
  path: string;
  encrypted: boolean;
  version: number;
  compressed: boolean;
}

export interface CloudSyncRoot {
  provider: string;
  path: string;
  reason: string;
}

export interface CloudBackupHit {
  provider: string;
  kind: "iOS-MobileSync" | "Android-AB" | string;
  path: string;
  sizeBytes: number;
  cloudRoot: string;
  description: string;
}

export interface AndroidPartition {
  name: string;
  blockNode: string;
  sizeBytes: number;
}

export interface IOSDevice {
  udid: string;
  model: string;
  name: string;
  iosVer: string;
  trusted: boolean;
}

export interface PTPDevice {
  model: string;
  port: string;
}

export interface MTPDevice {
  serial: string;
  state: string;
  model?: string;
  product?: string;
  transportID?: string;
}

// =============================================================================
// WailsApp interface —— 强类型签名 + index signature 兜底
// =============================================================================

export interface WailsApp {
  // ---- 启动 / 系统 ----
  GetAppVersion(): string | Promise<string>;
  IsAdmin(): boolean | Promise<boolean>;
  Platform(): string | Promise<string>;

  // ---- 扫描 ----
  GetDrives(): Promise<DriveInfo[]>;
  StartScan(drivePath: string, mode: string): Promise<void>;
  StopScan(): void | Promise<void>;
  GetScanResults(): Promise<unknown>;
  ReadFilePreview(fileID: string, maxBytes: number): Promise<Uint8Array | string>;

  // ---- 恢复 ----
  StartRecovery(fileIDs: string[], outputDir: string): Promise<void>;
  StartRecoveryWithOptions(
    fileIDs: string[],
    outputDir: string,
    allowSameDisk: boolean,
    archiveByExifDate: boolean,
  ): Promise<void>;
  RetryFailedRecovery(outputDir: string): Promise<void>;
  GetLastRecoveryRecords(): Promise<FileRecoveryRecord[]>;

  // ---- 更新 ----
  CheckForUpdate(): Promise<UpdateCheckResult>;
  DownloadUpdate(version: string, assetURL: string, assetName: string, assetSize: number): Promise<void>;
  ApplyPendingUpdate(): Promise<void>;
  GetPendingUpdate(): Promise<{ version: string } | null>;
  CancelPendingUpdate(): Promise<void>;

  // ---- 移动端 / 备份 ----
  DiscoverIOSBackups(): Promise<IOSBackupInfo[]>;
  StartIOSBackupScan(backupPath: string, password: string): Promise<void>;
  SelectAndroidBackup(): Promise<string>;
  InspectAndroidBackup(path: string): Promise<AndroidBackupInfo>;
  StartAndroidBackupScan(path: string, password: string): Promise<void>;
  MTPCheck(): Promise<{ available: boolean; version?: string; installURL?: string }>;
  MTPListDevices(): Promise<MTPDevice[]>;
  MTPPullDirectoryAndScan(serial: string, src: string, dst: string, mode: string): Promise<void>;
  AndroidIsRooted(serial: string): Promise<boolean>;
  AndroidListPartitions(serial: string): Promise<AndroidPartition[]>;
  AndroidDumpPartitionAndScan(serial: string, blockNode: string, outImg: string, mode: string): Promise<void>;
  PTPCheck(): Promise<{ available: boolean; version?: string }>;
  PTPListDevices(): Promise<PTPDevice[]>;
  PTPPullAllAndScan(port: string, destDir: string, mode: string): Promise<void>;
  IOSDirectCheck(): Promise<{ available: boolean }>;
  IOSListDevices(): Promise<IOSDevice[]>;
  IOSPair(udid: string): Promise<void>;
  IOSTriggerBackupAndScan(udid: string, destDir: string, password: string): Promise<void>;

  // ---- 云端 ----
  DiscoverCloudSyncRoots(): Promise<CloudSyncRoot[]>;
  ScanCloudForBackups(): Promise<CloudBackupHit[]>;

  // ---- NAS ----
  StartSMBScan(req: Record<string, unknown>): Promise<void>;
  StartNFSScan(req: Record<string, unknown>): Promise<void>;
  StopNASScan(): Promise<void>;

  // ---- 镜像 / 取消 ----
  DumpDisk(srcDevicePath: string, dstImagePath: string): Promise<void>;
  CancelAndroidDump(): Promise<void>;
  CancelMTPPull(): Promise<void>;
  CancelIOSBackup(): Promise<void>;
  CancelPTPPull(): Promise<void>;
  CancelDiskDump(): Promise<void>;

  // ---- 兜底：上面没列的 IPC 走这里，类型 any（编译过得去，自动完成弱） ----
  [methodName: string]: (...args: any[]) => unknown;
}

export {};
