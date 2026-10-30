import { describe, it, expect } from "vitest";
import { analyze } from "@/lib/detector";
import { buildPreviewDoc, findings, predictPage, realOwner } from "@/lib/sandbox";

describe("safe preview", () => {
  it("reveals the real owner behind a lookalike", () => {
    expect(realOwner("https://secure-update-bank.account-verify.xyz/login")).toBe("account-verify.xyz");
  });
  it("predicts a fake login page", () => {
    expect(predictPage(analyze("http://192.168.4.20/paypal-login/verify-account.php"))).toBe("credential");
  });
  it("flags brand impersonation", () => {
    expect(findings(analyze("http://192.168.4.20/paypal-login")).some((f) => f.title.includes("Paypal"))).toBe(true);
  });
  it("escapes payload and blocks scripts in the sandbox", () => {
    const doc = buildPreviewDoc(analyze("javascript:alert('<script>x</script>')"));
    expect(doc).not.toContain("<script>x");
    expect(doc).toContain("default-src 'none'");
  });
});
