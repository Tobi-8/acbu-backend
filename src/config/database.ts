import { PrismaClient, Prisma } from "@prisma/client";
import { withAccelerate } from "@prisma/extension-accelerate";
import { config } from "./env";
import { logger } from "./logger";
import { trace, SpanStatusCode } from "@opentelemetry/api";
import { encryptKycPayload, decryptKycPayload } from "../utils/kycEncryption";

// B-056: Validate URL assignments at boot to prevent runtime/migration confusion.
// DATABASE_URL  → direct PostgreSQL only (used by prisma migrate)
// PRISMA_ACCELERATE_URL → prisma:// or prisma+postgres:// protocol (runtime connection pooling)
const ACCELERATE_PROTOCOL_RE = /^prisma(\+postgres)?:\/\//i;

if (ACCELERATE_PROTOCOL_RE.test(config.databaseUrl)) {
  throw new Error(
    "[database] DATABASE_URL must be a direct PostgreSQL connection string " +
      "(postgresql:// or postgres://). " +
      "An Accelerate URL (prisma://) was detected — " +
      "set that value in PRISMA_ACCELERATE_URL instead. " +
      "Using Accelerate for migrations will fail.",
  );
}

if (
  config.prismaAccelerateUrl &&
  !ACCELERATE_PROTOCOL_RE.test(config.prismaAccelerateUrl)
) {
  logger.warn(
    "[database] PRISMA_ACCELERATE_URL does not start with prisma:// — " +
      "expected an Accelerate connection string. " +
      "If you intended a direct URL, set DATABASE_URL and leave PRISMA_ACCELERATE_URL unset.",
  );
}

const useAccelerate = Boolean(config.prismaAccelerateUrl);
const databaseUrl = useAccelerate
  ? config.prismaAccelerateUrl!
  : config.databaseUrl;

logger.info(
  `[database] Runtime connection: ${useAccelerate ? "Prisma Accelerate (pooled)" : "direct PostgreSQL"}`,
);
logger.info(
  "[database] Migration connection: direct PostgreSQL via DATABASE_URL " +
    "(run prisma migrate against DATABASE_URL, never against PRISMA_ACCELERATE_URL)",
);

const basePrisma = new PrismaClient({
  datasources: { db: { url: databaseUrl } },
  log: [
    { level: "query", emit: "event" },
    { level: "error", emit: "stdout" },
    { level: "warn", emit: "stdout" },
  ],
});

// Retry config for connection pool exhaustion (Prisma Accelerate)
const MAX_RETRIES = 3;
const BASE_BACKOFF_MS = 200;

function isPoolExhaustionError(err: unknown): boolean {
  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    return err.code === "P2024";
  }
  return false;
}

// OTel: wrap every Prisma query in a span so traces link DB calls to parent spans
basePrisma.$use(async (params, next) => {
  const tracer = trace.getTracer("prisma");
  const spanName = `prisma.${params.model ?? "raw"}.${params.action}`;
  return tracer.startActiveSpan(spanName, async (span) => {
    span.setAttributes({
      "db.system": "postgresql",
      "db.operation": params.action,
      ...(params.model ? { "db.prisma.model": params.model } : {}),
    });
    try {
      const result = await next(params);
      span.setStatus({ code: SpanStatusCode.OK });
      return result;
    } catch (err) {
      span.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
      throw err;
    } finally {
      span.end();
    }
  });
});

// KYC payload encryption middleware: encrypt sensitive extracted/redacted data before write,
// decrypt after read. Uses AES-256-GCM via PII_ENCRYPTION_KEY.
const KYC_PAYLOAD_FIELDS = ["machineExtractedPayload", "machineRedactedPayload"] as const;

function encryptKycData(data: Record<string, unknown>): void {
  for (const field of KYC_PAYLOAD_FIELDS) {
    if (data[field] !== undefined) {
      data[field] = encryptKycPayload(data[field]);
    }
  }
}

function decryptKycData(data: Record<string, unknown>): void {
  for (const field of KYC_PAYLOAD_FIELDS) {
    if (typeof data[field] === "string") {
      data[field] = decryptKycPayload(data[field] as string);
    }
  }
}

basePrisma.$use(async (params, next) => {
  if (params.model === "KycApplication") {
    // Encrypt before writes
    if (["create", "update", "updateMany"].includes(params.action)) {
      const args = params.args as Record<string, unknown> | undefined;
      if (args?.data && typeof args.data === "object") {
        encryptKycData(args.data as Record<string, unknown>);
      }
    }
    if (params.action === "upsert") {
      const args = params.args as Record<string, unknown> | undefined;
      if (args?.create && typeof args.create === "object") {
        encryptKycData(args.create as Record<string, unknown>);
      }
      if (args?.update && typeof args.update === "object") {
        encryptKycData(args.update as Record<string, unknown>);
      }
    }
  }

  const result = await next(params);

  // Decrypt after reads
  if (params.model === "KycApplication") {
    if (["findUnique", "findFirst", "findUniqueOrThrow", "findFirstOrThrow"].includes(params.action)) {
      if (result && typeof result === "object") {
        decryptKycData(result as Record<string, unknown>);
      }
    }
    if (params.action === "findMany") {
      if (Array.isArray(result)) {
        for (const row of result) {
          decryptKycData(row as Record<string, unknown>);
        }
      }
    }
  }

  return result;
});

// Connection pool exhaustion retry middleware: retry with exponential backoff
// when Prisma Accelerate returns P2024 (connection pool timeout).
// Retries up to MAX_RETRIES-1 times (attempt 1 = first try, attempt 4 throws).
basePrisma.$use(async (params, next) => {
  let lastError: unknown;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await next(params);
    } catch (err) {
      if (!isPoolExhaustionError(err)) {
        throw err;
      }
      if (attempt < MAX_RETRIES) {
        lastError = err;
        const backoff = BASE_BACKOFF_MS * 2 ** (attempt - 1);
        logger.warn("Prisma connection pool exhausted, retrying", {
          model: params.model,
          action: params.action,
          attempt,
          maxRetries: MAX_RETRIES,
          backoffMs: backoff,
        });
        await new Promise((r) => setTimeout(r, backoff));
      } else {
        throw err;
      }
    }
  }
  throw lastError;
});

export const prisma = useAccelerate
  ? basePrisma.$extends(withAccelerate())
  : basePrisma;

// Log queries in development ($on exists only on base client, not on extended proxy)
if (config.nodeEnv === "development") {
  basePrisma.$on(
    "query" as never,
    (e: { query: string; params: string; duration: number }) => {
      logger.debug("Query", {
        query: e.query,
        params: e.params,
        duration: `${e.duration}ms`,
      });
    },
  );
}

// Handle graceful shutdown
process.on("beforeExit", async () => {
  await basePrisma.$disconnect();
});

export default prisma;
