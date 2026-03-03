import type { NextApiRequest, NextApiResponse } from "next";

import { withAethelredApiRoute } from "@aethelred/sdk";

export default withAethelredApiRoute(
  async (req: NextApiRequest, res: NextApiResponse) => {
    const body = (req.body ?? {}) as { text?: string };
    const text = body.text ?? "";
    const normalized = text.trim().replace(/\s+/g, " ");

    res.status(200).json({
      normalized,
      framework: "nextjs-pages-router",
      headerPrefix: process.env.AETHELRED_HEADER_PREFIX ?? "x-aethelred",
    });
  },
  {
    service: "nextjs-verifier-sample",
    component: "legacy-verify-route",
  },
);
