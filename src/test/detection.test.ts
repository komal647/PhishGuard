import { describe, it, expect } from "vitest";
import { performLocalDetection, detectPhishing } from "../lib/api";

describe("Phishing Detection Engine", () => {
  it("should classify legitimate domains as safe", async () => {
    const result = await performLocalDetection("https://google.com", "url");
    expect(result.label).toBe("safe");
    expect(result.risk_percentage).toBeLessThan(30);
  });

  it("should detect typosquatting and character substitution lookalikes", async () => {
    const result = await performLocalDetection("http://paypa1-verify-account.xyz", "url");
    expect(result.label).toBe("phishing");
    expect(result.risk_percentage).toBeGreaterThanOrEqual(50);
    expect(result.details.indicators.some(i => i.name.includes("Lookalike") || i.name.includes("Typosquatting") || i.name.includes("High-Risk"))).toBe(true);
  });

  it("should detect subdomain brand spoofing", async () => {
    const result = await performLocalDetection("http://login.paypal.com.untrusted-site.top", "url");
    expect(result.label).toBe("phishing");
    expect(result.details.indicators.some(i => i.description.includes("paypal"))).toBe(true);
  });

  it("should flag high-pressure SMS scams with cryptocurrency wallet addresses", async () => {
    const sms = "URGENT: Your account has been suspended! Transfer funds to 0x71C7656EC7ab88b098defB751B7401B5f6d8976F within 24 hours to reactivate.";
    const result = await performLocalDetection(sms, "sms");
    expect(["suspicious", "phishing"]).toContain(result.label);
    expect(result.details.indicators.some(i => i.name.includes("High-Pressure") || i.name.includes("Cryptocurrency"))).toBe(true);
  });

  it("should detect credential harvesting and dangerous file attachment mentions", async () => {
    const email = "Dear User, Please verify your password immediately by opening the attached document security_update.exe";
    const result = await performLocalDetection(email, "email");
    expect(result.label).toBe("phishing");
    expect(result.details.indicators.some(i => i.name.includes("Credential") || i.name.includes("Dangerous"))).toBe(true);
  });

  it("should classify legitimate Amazon 2FA/OTP message as safe", async () => {
    const sample = "Your OTP for logging into Amazon is 482910. Do not share this code with anyone. Amazon will never call you for this code.";
    const result = await performLocalDetection(sample, "sms");
    expect(result.label).toBe("safe");
    expect(result.risk_percentage).toBeLessThan(15);
  });

  it("should detect IndiaPost package redelivery fee phishing scam", async () => {
    const sample = "Delivery Notice: Your IndiaPost package could not be delivered because of an incomplete address. Pay a redelivery fee of ₹19 here: example-phish.net";
    const result = await performLocalDetection(sample, "sms");
    expect(result.label).toBe("phishing");
    expect(result.risk_percentage).toBeGreaterThanOrEqual(50);
    expect(result.details.indicators.some(i => i.name.includes("Package Redelivery") || i.name.includes("Brand-Keyword") || i.name.includes("Explicit Malicious"))).toBe(true);
  });

  it("should detect high character entropy on DGA generated domains", async () => {
    const sample = "http://x17z-pay-update-verification.com";
    const result = await performLocalDetection(sample, "url");
    expect(result.details.indicators.some(i => i.name.includes("Entropy") || i.name.includes("Phishing Keyword"))).toBe(true);
  });

  it("should detect OAuth Device Code Phishing attack targeting official Microsoft domain", async () => {
    const sample = "[IT Support Alert] Critical patch deployment for your enterprise email client. Please authorize the secure IT-Migration-Assistant terminal. Go to https://microsoft.com and enter the session validation token: B7X-9RK-M32";
    const result = await performLocalDetection(sample, "email");
    expect(result.label).toBe("phishing");
    expect(result.risk_percentage).toBeGreaterThanOrEqual(50);
    expect(result.details.indicators.some(i => i.name.includes("Device Code Phishing"))).toBe(true);
  });

  it("should classify genuine automated integration notice as safe", async () => {
    const sample = "You are receiving this automated notice because your Zoom account has requested permission to integrate with your Google Calendar. If you did not initiate this request, you can safely ignore this or review your app permissions at https://google.com";
    const result = await performLocalDetection(sample, "email");
    expect(result.label).toBe("safe");
    expect(result.risk_percentage).toBeLessThan(20);
  });

  it("should classify genuine AWS budget alert linking to amazon.com as safe", async () => {
    const sample = "[AWS Notification] Action Required: Your AWS Account (ID: 4892-0192-3841) has exceeded 85% of its monthly budget threshold for the current billing cycle. Please review your billing dashboard immediately to avoid overage charges: https://amazon.com";
    const result = await performLocalDetection(sample, "email");
    expect(result.label).toBe("safe");
    expect(result.risk_percentage).toBeLessThan(20);
  });

  it("should verify detectPhishing wrapper preserves safe verdict for Case D", async () => {
    const sample = "You are receiving this automated notice because your Zoom account has requested permission to integrate with your Google Calendar. If you did not initiate this request, you can safely ignore this or review your app permissions at https://google.com";
    const result = await detectPhishing(sample, "email");
    expect(result.label).toBe("safe");
    expect(result.risk_percentage).toBeLessThan(20);
  });
});
