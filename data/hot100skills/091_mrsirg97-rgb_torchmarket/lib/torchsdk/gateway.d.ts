/**
 * Gateway URL utilities for Irys content
 * Use uploader.irys.xyz as fallback when gateway.irys.xyz has issues
 */
/**
 * Convert an Irys gateway URL to uploader URL (fallback)
 */
export declare const irysToUploader: (url: string) => string;
/**
 * Check if URL is from Irys gateway
 */
export declare const isIrysUrl: (url: string) => boolean;
/**
 * Fetch with automatic fallback from gateway.irys.xyz to uploader.irys.xyz
 */
export declare const fetchWithFallback: (url: string, options?: RequestInit, timeoutMs?: number) => Promise<Response>;
//# sourceMappingURL=gateway.d.ts.map