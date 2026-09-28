// A user's SP sessions (D-043), for the host's "sign out of all applications" and retries after
// an out-of-band session end. Server-only: it has no URL, so no browser can call it.
import { createAuthEndpoint } from "better-auth/api";
import * as z from "zod";
import { listUserParticipants } from "../storage/participants";
import { lookupLog, type PluginState } from "./issue";

export const listSessionParticipantsEndpoint = (state: PluginState) =>
  createAuthEndpoint.serverOnly({ method: "POST", body: z.object({ userId: z.string().min(1).max(255) }) }, async (ctx) => {
    const { participants: rows, truncated } = await listUserParticipants(ctx.context.adapter as any, ctx.body.userId);
    const participants = await Promise.all(
      rows.map(async (p) => ({ ...p, entityId: (await state.directory.byId(ctx.context.adapter as any, p.spId, lookupLog(ctx)))?.entityId })),
    );
    return ctx.json({ participants, truncated });
  });
