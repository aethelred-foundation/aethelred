const sealInput = document.getElementById("sealInput");
const output = document.getElementById("output");
const verifyBtn = document.getElementById("verifyBtn");
const clearBtn = document.getElementById("clearBtn");

function stableSort(value) {
  if (Array.isArray(value)) return value.map(stableSort);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = stableSort(value[k]);
    return out;
  }
  return value;
}

async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return (
    "0x" +
    Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

async function verifySealOffline(payload) {
  const seal = payload && payload.seal && typeof payload.seal === "object" ? payload.seal : payload;
  const checks = [];
  const required = [
    "id",
    "jobId",
    "modelHash",
    "inputCommitment",
    "outputCommitment",
    "status",
    "requester",
    "createdAt",
    "validators",
  ];
  for (const key of required) {
    checks.push({
      id: `required:${key}`,
      ok: seal && seal[key] !== undefined && seal[key] !== null,
      severity: "error",
      message: seal && seal[key] !== undefined ? `${key} present` : `Missing ${key}`,
    });
  }

  let expiryWarning = null;
  if (seal?.expiresAt) {
    const ts = new Date(seal.expiresAt);
    if (!Number.isNaN(ts.getTime()) && ts.getTime() <= Date.now()) {
      expiryWarning = "Seal is expired";
      checks.push({ id: "lifecycle:expiry", ok: false, severity: "warning", message: expiryWarning });
    } else {
      checks.push({ id: "lifecycle:expiry", ok: true, severity: "info", message: "Seal not expired" });
    }
  }

  const validators = Array.isArray(seal?.validators) ? seal.validators : [];
  checks.push({
    id: "validators:count",
    ok: validators.length > 0,
    severity: "error",
    message: validators.length > 0 ? `${validators.length} validator attestations present` : "No validator attestations",
  });

  const canonical = JSON.stringify(stableSort(seal));
  const fingerprintSha256 = await sha256Hex(canonical);
  const errors = checks.filter((c) => c.severity === "error" && !c.ok).map((c) => c.message);
  const warnings = checks.filter((c) => c.severity === "warning" && !c.ok).map((c) => c.message);
  return {
    valid: errors.length === 0,
    fingerprintSha256,
    checks,
    errors,
    warnings,
    score: Math.max(0, 100 - errors.length * 25 - warnings.length * 8),
  };
}

verifyBtn.addEventListener("click", async () => {
  try {
    const raw = sealInput.value.trim();
    if (!raw) throw new Error("Paste a seal JSON payload first.");
    const parsed = JSON.parse(raw);
    const result = await verifySealOffline(parsed);
    output.textContent = JSON.stringify(result, null, 2);
    output.style.color = result.valid ? "#8be28b" : "#ffb4b4";
    chrome.storage?.local?.set?.({ lastSealPayload: raw }).catch?.(() => {});
  } catch (error) {
    output.textContent = String(error.message || error);
    output.style.color = "#ffb4b4";
  }
});

clearBtn.addEventListener("click", () => {
  sealInput.value = "";
  output.textContent = "";
});

chrome.storage?.local?.get?.(["lastSealPayload"], (data) => {
  if (data?.lastSealPayload && !sealInput.value) {
    sealInput.value = data.lastSealPayload;
  }
});
