import { describe, expect, it } from "vitest";
import { analyze } from "@/lib/detector";

describe("QR detector", () => {
  it("rates a normal https site as safe", () => {
    expect(analyze("https://www.wikipedia.org").label).toBe("safe");
  });
  it("flags an IP-hosted phishing login as malicious", () => {
    expect(analyze("http://192.168.4.20/paypal-login/verify-account.php").label).toBe("malicious");
  });
  it("flags javascript: payloads as malicious", () => {
    expect(analyze("javascript:alert(1)").label).toBe("malicious");
  });
});
