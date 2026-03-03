/**
 * Next.js integration examples for Aethelred TypeScript SDK.
 *
 * Pages Router:
 *   export default withAethelredApiRoute(async (req, res) => { ... })
 *
 * App Router:
 *   export const POST = withAethelredRouteHandler(async (request) => { ... })
 */

import {
  withAethelredApiRoute,
  withAethelredRouteHandler,
} from "@aethelred/sdk/integrations";

export const pagesApiHandler = withAethelredApiRoute(
  async (req, res) => {
    const body = (req.body ?? {}) as { prompt?: string };
    res.statusCode = 200;
    res.json?.({
      completion: `Verified response for: ${body.prompt ?? "unknown"}`,
      provider: "aethelred-demo",
    });
  },
  {
    service: "nextjs-chat-api",
    component: "chat-completions",
    onRecord: (envelope) => {
      // Replace with your telemetry sink or bridge submitter
      console.log("Aethelred verification envelope", envelope);
    },
  },
);

export const appRoutePost = withAethelredRouteHandler(
  async (request) => {
    const payload = (await request.json()) as { prompt: string };
    return new Response(
      JSON.stringify({
        completion: `Verified app-route response for: ${payload.prompt}`,
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    );
  },
  {
    service: "nextjs-app-router",
    component: "chat-route",
  },
);
