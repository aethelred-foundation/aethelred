import { withAethelredRouteHandler } from "@aethelred/sdk";

export const GET = withAethelredRouteHandler(
  async () =>
    new Response(
      JSON.stringify({
        status: "ok",
        service: "aethelred-nextjs-verifier-sample",
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    ),
  {
    service: "nextjs-verifier-sample",
    component: "health-route",
  },
);
