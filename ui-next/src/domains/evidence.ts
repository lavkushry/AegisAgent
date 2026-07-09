import {
  downloadFromGateway,
  type FetchOptions,
} from "@/lib/http/client";

export interface EvidenceExportRequest {
  run_id?: string;
  from?: string;
  to?: string;
}

/**
 * Phase 8.3 investigation evidence pack.
 * POST /v1/evidence/export → ZIP blob.
 */
export function exportInvestigationEvidence(
  opts: FetchOptions,
  body: EvidenceExportRequest = {},
): Promise<Blob> {
  return downloadFromGateway(opts, "/v1/evidence/export", "POST", body);
}

/** Tenant compliance pack (SOC2-oriented). */
export function downloadComplianceEvidencePack(
  opts: FetchOptions,
): Promise<Blob> {
  return downloadFromGateway(opts, "/v1/compliance/evidence-pack");
}
