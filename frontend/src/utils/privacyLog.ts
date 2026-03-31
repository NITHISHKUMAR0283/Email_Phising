/**
 * Privacy Log Utility
 * - Track user actions for privacy/audit purposes
 * - Persist to localStorage and backend
 */

export enum PrivacyEventType {
  CHAT_QUERY = "chat_query",
  REPORT_GENERATED = "report_generated",
  EMAIL_VIEWED = "email_viewed",
  API_CALL = "api_call",
  EXPORT_DATA = "export_data",
}

export interface PrivacyLogEntry {
  event: PrivacyEventType;
  userId?: string;
  timestamp: string;
  action: string;
  emailId?: string;
  details?: Record<string, unknown>;
}

const PRIVACY_LOG_KEY = "phishguard_privacy_log";
const SESSION_ID = `session_${new Date().getTime()}`;

/**
 * Append event to privacy log
 * - Store in localStorage
 * - Send to backend asynchronously
 */
export const appendPrivacyLog = async (
  event: PrivacyEventType,
  action: string,
  emailId?: string,
  details?: Record<string, unknown>
): Promise<void> => {
  const entry: PrivacyLogEntry = {
    event,
    userId: SESSION_ID,
    timestamp: new Date().toISOString(),
    action,
    emailId,
    details,
  };

  // Add to localStorage
  try {
    const existing = localStorage.getItem(PRIVACY_LOG_KEY);
    const log: PrivacyLogEntry[] = existing ? JSON.parse(existing) : [];
    log.push(entry);
    // Keep only last 100 entries
    if (log.length > 100) {
      log.shift();
    }
    localStorage.setItem(PRIVACY_LOG_KEY, JSON.stringify(log));
  } catch (err) {
    console.error("Failed to write privacy log to localStorage:", err);
  }

  // Send to backend asynchronously (fire-and-forget)
  try {
    await fetch("http://localhost:8000/api/audit/privacy-log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        event,
        action,
        userId: SESSION_ID,
        emailId,
        details,
      }),
    });
  } catch (err) {
    console.error("Failed to send privacy log to backend:", err);
  }
};

/**
 * Get privacy log from localStorage
 */
export const getPrivacyLog = (): PrivacyLogEntry[] => {
  try {
    const existing = localStorage.getItem(PRIVACY_LOG_KEY);
    return existing ? JSON.parse(existing) : [];
  } catch (err) {
    console.error("Failed to read privacy log from localStorage:", err);
    return [];
  }
};

/**
 * Clear privacy log (for testing/reset)
 */
export const clearPrivacyLog = (): void => {
  try {
    localStorage.removeItem(PRIVACY_LOG_KEY);
  } catch (err) {
    console.error("Failed to clear privacy log:", err);
  }
};
