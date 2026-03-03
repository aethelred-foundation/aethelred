import { withAethelredRouteHandler } from "@aethelred/sdk";

function classifyPrompt(prompt: string) {
  const risky = /wire|urgent|override|password|otp|bypass/i.test(prompt);
  return {
    label: risky ? "RISK" : "SAFE",
    score: risky ? 0.98 : 0.07,
  };
}

export const POST = withAethelredRouteHandler(
  async (request) => {
    const payload = (await request.json()) as { prompt?: string };
    const prompt = payload.prompt ?? "";
    const result = classifyPrompt(prompt);

    return new Response(
      JSON.stringify({
        prompt,
        ...result,
        mode: process.env.AETHELRED_VERIFY_MODE ?? "seal-envelope",
        rpcUrl: process.env.AETHELRED_RPC_URL ?? null,
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    );
  },
  {
    service: "nextjs-verifier-sample",
    component: "verify-app-route",
  },
);
