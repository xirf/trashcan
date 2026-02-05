import { fetch } from "bun";

const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";

export async function verifyTurnstile(token?: string): Promise<boolean> {
  if (!TURNSTILE_SECRET) return false;
  if (!token) return false;
  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      secret: TURNSTILE_SECRET,
      response: token,
    }).toString(),
  });
  if (!res.ok) return false;
  const data = (await res.json()) as { success?: boolean };
  return !!data.success;
}
