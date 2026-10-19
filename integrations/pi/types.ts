export interface ProtectedInputNotice {
  version: number;
  request_id: string;
  request_revision: number;
  host_session_id: string;
  data_kind: string;
  recipient_id: string;
  recipient_label: string;
  consumption: string;
  expires_at: string;
  input_mode: "external_tty" | "host_native_verified" | "url" | "unavailable";
  input_assurance: string;
  untrusted_purpose?: string;
}

// The trusted client surface the protected-input component needs. Kept
// structural so the component can be exercised with a stub in tests.
export interface SeqPassInputClient {
  fulfill(requestID: string, revision: number, value: string): Promise<void>;
  dismissPrompt(requestID: string): Promise<void>;
}
