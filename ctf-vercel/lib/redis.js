import { Redis } from "@upstash/redis";

// Works with either the Upstash-native env vars or Vercel's KV integration vars.
// automaticDeserialization is OFF so every value comes back as a predictable
// string — we parse numbers/JSON ourselves, avoiding surprises (e.g. a username
// that looks like a number being coerced).
export const redis = new Redis({
  url:   process.env.UPSTASH_REDIS_REST_URL   || process.env.KV_REST_API_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN,
  automaticDeserialization: false,
});
