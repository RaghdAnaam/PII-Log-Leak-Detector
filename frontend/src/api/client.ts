/// <reference types="vite/client" />

import type { ScanResultResponse } from "../types";

const API_BASE =
  (import.meta.env.VITE_API_URL as string | undefined) ?? "";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}/api${path}`, options);
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) message = body.detail;
    } catch {
      // ignore parse errors
    }
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export async function scanDemo(): Promise<ScanResultResponse> {
  return request<ScanResultResponse>("/scan/demo", { method: "POST" });
}

export async function getScan(scanId: string): Promise<ScanResultResponse> {
  return request<ScanResultResponse>(`/scan/${scanId}`);
}

export async function fixScan(scanId: string): Promise<ScanResultResponse> {
  return request<ScanResultResponse>(`/scan/${scanId}/fix`, { method: "POST" });
}

export async function rescan(scanId: string): Promise<ScanResultResponse> {
  return request<ScanResultResponse>(`/scan/${scanId}/rescan`, {
    method: "POST",
  });
}
