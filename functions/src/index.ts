import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import fetch from "node-fetch";

admin.initializeApp();

// ─── Types ───────────────────────────────────────────────────────────────────

interface ApiStatus {
  name: string;
  status: "online" | "error" | "missing" | "testing";
  message?: string;
}

interface ThreatIndicator {
  name: string;
  severity: "low" | "medium" | "high";
  description: string;
}

interface ThreatAuditSources {
  virustotal?: {
    scanned: boolean;
    malicious: number;
    suspicious: number;
    verdict: "clean" | "suspicious" | "malicious";
  };
  google_safe_browsing?: {
    scanned: boolean;
    matches: string[];
  };
  phishtank?: {
    scanned: boolean;
    found: boolean;
    verified: boolean;
  };
  [key: string]: unknown;
}

// ─── Helper: read secrets from environment ───────────────────────────────────

function getApiKeys() {
  return {
    VIRUSTOTAL_KEY: process.env.VIRUSTOTAL_KEY || process.env.VITE_VIRUSTOTAL_KEY || "",
    GOOGLE_SAFE_BROWSING_KEY: process.env.GOOGLE_SAFE_BROWSING_KEY || process.env.VITE_GOOGLE_SAFE_BROWSING_KEY || "",
    PHISHTANK_KEY: process.env.PHISHTANK_KEY || process.env.VITE_PHISHTANK_KEY || "",
    IPQUALITYSCORE_KEY: process.env.IPQUALITYSCORE_KEY || process.env.VITE_IPQUALITYSCORE_KEY || "",
    CLOUDMERSIVE_KEY: process.env.CLOUDMERSIVE_KEY || process.env.VITE_CLOUDMERSIVE_KEY || "",
    URLHAUS_KEY: process.env.URLHAUS_KEY || process.env.VITE_URLHAUS_KEY || "",
  };
}

// ─── detectPhishing Cloud Function ───────────────────────────────────────────
// Called from the frontend via httpsCallable.
// Receives: { urls: string[] }
// Returns:  { indicators, threat_audit, score }

export const detectPhishing = functions.https.onCall(
  async (request: functions.https.CallableRequest<{ urls: string[] }>) => {
    const urls: string[] = request.data?.urls || [];
    const keys = getApiKeys();

    const indicators: ThreatIndicator[] = [];
    let score = 0;
    const threat_audit: { scan_time: string; sources: ThreatAuditSources } = {
      scan_time: new Date().toISOString(),
      sources: {},
    };

    for (const url of urls) {
      const cleanUrl = url.startsWith("http") ? url : `https://${url}`;

      // 1. VirusTotal
      if (keys.VIRUSTOTAL_KEY) {
        try {
          const encodedId = Buffer.from(cleanUrl)
            .toString("base64")
            .replace(/=/g, "");
          const res = await fetch(
            `https://www.virustotal.com/api/v3/urls/${encodedId}`,
            {
              method: "GET",
              headers: {
                "x-apikey": keys.VIRUSTOTAL_KEY,
                Accept: "application/json",
              },
            }
          );
          if (res.ok) {
            const data = (await res.json()) as any;
            const stats = data.data?.attributes?.last_analysis_stats;
            if (stats) {
              threat_audit.sources.virustotal = {
                scanned: true,
                malicious: stats.malicious,
                suspicious: stats.suspicious,
                verdict:
                  stats.malicious > 0
                    ? "malicious"
                    : stats.suspicious > 0
                      ? "suspicious"
                      : "clean",
              };
              if (stats.malicious > 0) {
                indicators.push({
                  name: "VirusTotal Flag",
                  severity: "high",
                  description: `Flagged malicious by ${stats.malicious} security vendors on VT`,
                });
                score += 60;
              }
            }
          }
        } catch (e: any) {
          console.warn("VT Error:", e.message);
        }
      }

      // 2. Google Safe Browsing
      if (keys.GOOGLE_SAFE_BROWSING_KEY) {
        try {
          const payload = {
            client: {clientId: "phishguard", clientVersion: "1.0.0"},
            threatInfo: {
              threatTypes: [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
              ],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{url: cleanUrl}],
            },
          };
          const res = await fetch(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${keys.GOOGLE_SAFE_BROWSING_KEY}`,
            {
              method: "POST",
              headers: {"Content-Type": "application/json"},
              body: JSON.stringify(payload),
            }
          );
          if (res.ok) {
            const data = (await res.json()) as {
              matches?: { threatType: string }[];
            };
            const matches = data.matches || [];
            threat_audit.sources.google_safe_browsing = {
              scanned: true,
              matches: matches.map((m) => m.threatType),
            };
            if (matches.length > 0) {
              indicators.push({
                name: "Google Safe Browsing",
                severity: "high",
                description: `Flagged as ${matches[0].threatType}`,
              });
              score += 100;
            }
          }
        } catch (e: any) {
          console.warn("GSB Error:", e.message);
        }
      }

      // 3. PhishTank
      if (keys.PHISHTANK_KEY && keys.PHISHTANK_KEY !== "your_phishtank_key_here") {
        try {
          const res = await fetch("https://checkurl.phishtank.com/checkurl/", {
            method: "POST",
            headers: {"Content-Type": "application/x-www-form-urlencoded"},
            body: new URLSearchParams({
              url: cleanUrl,
              format: "json",
              app_key: keys.PHISHTANK_KEY,
            }).toString(),
          });
          if (res.ok) {
            const data = (await res.json()) as any;
            const valid = data?.results?.valid;
            threat_audit.sources.phishtank = {
              scanned: true,
              found: data?.results?.in_database,
              verified: valid,
            };
            if (valid) {
              indicators.push({
                name: "PhishTank",
                severity: "high",
                description:
                  "Verified phishing URL in community database.",
              });
              score += 80;
            }
          }
        } catch (e: any) {
          console.warn("PhishTank Error:", e.message);
        }
      }

      // 4. IPQualityScore
      if (keys.IPQUALITYSCORE_KEY) {
        try {
          const encodedUrl = encodeURIComponent(cleanUrl);
          const res = await fetch(
            `https://www.ipqualityscore.com/api/json/url/${keys.IPQUALITYSCORE_KEY}/${encodedUrl}`
          );
          if (res.ok) {
            const data = (await res.json()) as any;
            if (data.success && data.unsafe && data.risk_score > 75) {
              const isHighRisk = data.risk_score > 90;
              indicators.push({
                name: "IPQualityScore",
                severity: isHighRisk ? "high" : "medium",
                description: `IPQS Flagged suspicious (Risk Score: ${data.risk_score})`,
              });
              score += isHighRisk ? 40 : 20;
            }
          }
        } catch (e: any) {
          console.warn("IPQS Error:", e.message);
        }
      }

      // 5. Cloudmersive
      if (keys.CLOUDMERSIVE_KEY && keys.CLOUDMERSIVE_KEY !== "your_cloudmersive_key_here") {
        try {
          const res = await fetch(
            "https://api.cloudmersive.com/virus/scan/website",
            {
              method: "POST",
              headers: {
                Apikey: keys.CLOUDMERSIVE_KEY,
                "Content-Type": "application/json",
              },
              body: JSON.stringify({Url: cleanUrl}),
            }
          );
          if (res.ok) {
            const data = (await res.json()) as any;
            if (data.CleanResult === false) {
              indicators.push({
                name: "Cloudmersive",
                severity: "high",
                description: "Website scanned as malicious/virus.",
              });
              score += 60;
            }
          }
        } catch (e: any) {
          console.warn("Cloudmersive Error:", e.message);
        }
      }

      // 6. URLhaus
      if (keys.URLHAUS_KEY) {
        try {
          const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
            method: "POST",
            headers: {"Content-Type": "application/x-www-form-urlencoded"},
            body: new URLSearchParams({url: cleanUrl}).toString(),
          });
          if (res.ok) {
            const data = (await res.json()) as any;
            if (data?.query_status === "ok") {
              indicators.push({
                name: "URLhaus",
                severity: "high",
                description:
                  "URL is tracked as malware distribution site by URLhaus.",
              });
              score += 80;
            }
          }
        } catch (e: any) {
          console.warn("URLhaus Error:", e.message);
        }
      }
    }

    return {
      indicators,
      threat_audit:
        Object.keys(threat_audit.sources).length > 0 ? threat_audit : null,
      score,
    };
  }
);

// ─── testApiConnections Cloud Function ───────────────────────────────────────
// Called from the frontend via httpsCallable.
// Receives: (nothing)
// Returns:  ApiStatus[]

export const testApiConnections = functions.https.onCall(
  async () => {
    const keys = getApiKeys();
    const results: ApiStatus[] = [];
    const testUrl = "http://example.com";

    // 1. VirusTotal
    if (keys.VIRUSTOTAL_KEY) {
      try {
        const encodedId = Buffer.from(testUrl)
          .toString("base64")
          .replace(/=/g, "");
        const res = await fetch(
          `https://www.virustotal.com/api/v3/urls/${encodedId}`,
          {
            method: "GET",
            headers: {
              "x-apikey": keys.VIRUSTOTAL_KEY,
              Accept: "application/json",
            },
          }
        );
        results.push({
          name: "VirusTotal",
          status: res.ok || res.status === 404 ? "online" : "error",
          message:
            res.ok || res.status === 404 ?
              "Connected API" :
              `HTTP Error ${res.status}`,
        });
      } catch (e: any) {
        results.push({
          name: "VirusTotal",
          status: "error",
          message: e.message || "Unknown error",
        });
      }
    } else {
      results.push({
        name: "VirusTotal",
        status: "missing",
        message: "API Key not configured in Firebase secrets",
      });
    }

    // 2. Google Safe Browsing
    if (keys.GOOGLE_SAFE_BROWSING_KEY) {
      try {
        const payload = {
          client: {clientId: "phishguard", clientVersion: "1.0.0"},
          threatInfo: {
            threatTypes: ["MALWARE"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{url: testUrl}],
          },
        };
        const res = await fetch(
          `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${keys.GOOGLE_SAFE_BROWSING_KEY}`,
          {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload),
          }
        );
        results.push({
          name: "Google Safe Browsing",
          status: res.ok ? "online" : "error",
          message: res.ok ? "Connected API" : `HTTP Error ${res.status}`,
        });
      } catch (e: any) {
        results.push({
          name: "Google Safe Browsing",
          status: "error",
          message: e.message || "Unknown error",
        });
      }
    } else {
      results.push({
        name: "Google Safe Browsing",
        status: "missing",
        message: "API Key not configured in Firebase secrets",
      });
    }

    // 3. PhishTank
    if (keys.PHISHTANK_KEY && keys.PHISHTANK_KEY !== "your_phishtank_key_here") {
      try {
        const res = await fetch("https://checkurl.phishtank.com/checkurl/", {
          method: "POST",
          headers: {"Content-Type": "application/x-www-form-urlencoded"},
          body: new URLSearchParams({
            url: testUrl,
            format: "json",
            app_key: keys.PHISHTANK_KEY,
          }).toString(),
        });
        results.push({
          name: "PhishTank",
          status: res.ok ? "online" : "error",
          message: res.ok ? "Connected API" : `HTTP Error ${res.status}`,
        });
      } catch (e: any) {
        results.push({
          name: "PhishTank",
          status: "error",
          message: e.message || "Unknown error",
        });
      }
    } else {
      results.push({
        name: "PhishTank",
        status: "missing",
        message: "API Key not configured in Firebase secrets",
      });
    }

    // 4. IPQualityScore
    if (keys.IPQUALITYSCORE_KEY) {
      try {
        const encodedUrl = encodeURIComponent(testUrl);
        const res = await fetch(
          `https://www.ipqualityscore.com/api/json/url/${keys.IPQUALITYSCORE_KEY}/${encodedUrl}`
        );
        results.push({
          name: "IPQualityScore",
          status: res.ok ? "online" : "error",
          message: res.ok ? "Connected API" : `HTTP Error ${res.status}`,
        });
      } catch (e: any) {
        results.push({
          name: "IPQualityScore",
          status: "error",
          message: e.message || "Unknown error",
        });
      }
    } else {
      results.push({
        name: "IPQualityScore",
        status: "missing",
        message: "API Key not configured in Firebase secrets",
      });
    }

    // 5. Cloudmersive
    if (keys.CLOUDMERSIVE_KEY && keys.CLOUDMERSIVE_KEY !== "your_cloudmersive_key_here") {
      try {
        const res = await fetch(
          "https://api.cloudmersive.com/virus/scan/website",
          {
            method: "POST",
            headers: {
              Apikey: keys.CLOUDMERSIVE_KEY,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({Url: testUrl}),
          }
        );
        results.push({
          name: "Cloudmersive",
          status: res.ok ? "online" : "error",
          message: res.ok ? "Connected API" : `HTTP Error ${res.status}`,
        });
      } catch (e: any) {
        results.push({
          name: "Cloudmersive",
          status: "error",
          message: e.message || "Unknown error",
        });
      }
    } else {
      results.push({
        name: "Cloudmersive",
        status: "missing",
        message: "API Key not configured in Firebase secrets",
      });
    }

    // 6. URLhaus
    if (keys.URLHAUS_KEY) {
      try {
        const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
          method: "POST",
          headers: {"Content-Type": "application/x-www-form-urlencoded"},
          body: new URLSearchParams({url: testUrl}).toString(),
        });
        results.push({
          name: "URLhaus",
          status: res.ok ? "online" : "error",
          message: res.ok ? "Connected API" : `HTTP Error ${res.status}`,
        });
      } catch (e: any) {
        results.push({
          name: "URLhaus",
          status: "error",
          message: e.message || "Unknown error",
        });
      }
    } else {
      results.push({
        name: "URLhaus",
        status: "missing",
        message: "API Key not configured in Firebase secrets",
      });
    }

    return {results};
  }
);
