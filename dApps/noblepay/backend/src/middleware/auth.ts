import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { PrismaClient, BusinessTier } from "@prisma/client";
import { logger } from "../lib/logger";

const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || "noblepay-dev-secret-change-in-production";

// Rate limits per business tier (requests per minute)
const TIER_RATE_LIMITS: Record<BusinessTier, number> = {
  STARTER: 60,
  STANDARD: 300,
  ENTERPRISE: 1000,
  INSTITUTIONAL: 5000,
};

// In-memory sliding window rate limiter per business
const rateLimitWindows = new Map<string, { count: number; resetAt: number }>();

export interface AuthenticatedRequest extends Request {
  businessId?: string;
  businessTier?: BusinessTier;
  apiKeyId?: string;
  jwtPayload?: JWTPayload;
}

interface JWTPayload {
  sub: string;
  businessId: string;
  tier: BusinessTier;
  iat: number;
  exp: number;
}

/**
 * Validate API key from Authorization header.
 * Expects: Authorization: Bearer <api-key>
 */
export async function authenticateAPIKey(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({
        error: "UNAUTHORIZED",
        message: "Missing or invalid Authorization header. Expected: Bearer <api-key>",
      });
      return;
    }

    const token = authHeader.slice(7);

    // First try JWT validation
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as JWTPayload;
      req.businessId = decoded.businessId;
      req.businessTier = decoded.tier;
      req.jwtPayload = decoded;
      next();
      return;
    } catch {
      // Not a JWT token, try API key
    }

    // Hash the provided key and look it up
    const keyHash = crypto.createHash("sha256").update(token).digest("hex");

    const apiKey = await prisma.aPIKey.findUnique({
      where: { keyHash },
      include: { business: true },
    });

    if (!apiKey) {
      res.status(401).json({
        error: "UNAUTHORIZED",
        message: "Invalid API key",
      });
      return;
    }

    if (apiKey.status !== "ACTIVE") {
      res.status(403).json({
        error: "FORBIDDEN",
        message: `API key is ${apiKey.status.toLowerCase()}`,
      });
      return;
    }

    if (apiKey.business.kycStatus === "SUSPENDED") {
      res.status(403).json({
        error: "FORBIDDEN",
        message: "Business account is suspended",
      });
      return;
    }

    // Update last used timestamp (fire-and-forget)
    prisma.aPIKey
      .update({
        where: { id: apiKey.id },
        data: { lastUsed: new Date() },
      })
      .catch((err) => logger.error("Failed to update API key last used", { error: err.message }));

    req.businessId = apiKey.businessId;
    req.businessTier = apiKey.business.tier;
    req.apiKeyId = apiKey.id;

    next();
  } catch (error) {
    logger.error("Authentication error", { error: (error as Error).message });
    res.status(500).json({
      error: "INTERNAL_ERROR",
      message: "Authentication service unavailable",
    });
  }
}

/**
 * Enforce per-business rate limits based on tier.
 */
export function tierRateLimit(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  const businessId = req.businessId;
  const tier = req.businessTier;

  if (!businessId || !tier) {
    next();
    return;
  }

  const limit = TIER_RATE_LIMITS[tier];
  const now = Date.now();
  const windowKey = `rate:${businessId}`;

  let window = rateLimitWindows.get(windowKey);

  if (!window || now > window.resetAt) {
    window = { count: 0, resetAt: now + 60_000 };
    rateLimitWindows.set(windowKey, window);
  }

  window.count++;

  // Set rate limit headers
  res.setHeader("X-RateLimit-Limit", limit);
  res.setHeader("X-RateLimit-Remaining", Math.max(0, limit - window.count));
  res.setHeader("X-RateLimit-Reset", Math.ceil(window.resetAt / 1000));

  if (window.count > limit) {
    res.status(429).json({
      error: "RATE_LIMITED",
      message: `Rate limit exceeded for ${tier} tier (${limit} req/min)`,
      retryAfter: Math.ceil((window.resetAt - now) / 1000),
    });
    return;
  }

  next();
}

/**
 * Generate a JWT token for a business.
 */
export function generateJWT(businessId: string, tier: BusinessTier): string {
  const payload: Omit<JWTPayload, "iat" | "exp"> = {
    sub: businessId,
    businessId,
    tier,
  };

  return jwt.sign(payload, JWT_SECRET, { expiresIn: "24h" });
}

/**
 * Generate a new API key for a business (returns raw key + hash).
 */
export function generateAPIKey(): { rawKey: string; keyHash: string } {
  const rawKey = `npk_${crypto.randomBytes(32).toString("hex")}`;
  const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
  return { rawKey, keyHash };
}

// Periodic cleanup of expired rate limit windows
setInterval(() => {
  const now = Date.now();
  for (const [key, window] of rateLimitWindows) {
    if (now > window.resetAt + 60_000) {
      rateLimitWindows.delete(key);
    }
  }
}, 300_000); // every 5 minutes
