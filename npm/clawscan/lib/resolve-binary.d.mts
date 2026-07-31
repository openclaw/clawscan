export type BinaryPlatform = "darwin" | "linux" | "win32";
export type BinaryArchitecture = "arm64" | "x64";

export declare function platformKey(platform?: string, arch?: string): string;

export declare function binaryFileName(platform?: string): string;

export declare function resolveBinaryPath(options: {
  packageRoot: string;
  platform?: string;
  arch?: string;
}): string;

export declare function resolveBundledBinaryPath(options?: {
  platform?: string;
  arch?: string;
}): string;
