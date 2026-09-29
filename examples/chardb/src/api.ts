import { CdbError } from "@chardb/core";
import { FileId } from "@chardb/core/files";
import { api } from "@chardb/core/server";
import { and, eq } from "drizzle-orm";
import { z } from "zod";
import { messages } from "./schema.ts";

export const postMessage = api.mutation({
  ref: "messages#create",
  authority: "organization",
  args: z.object({
    id: z.string(),
    organizationId: z.string(),
    body: z.string().trim().min(1).max(2_000),
    attachment: z.string().min(1).max(128).transform(FileId).nullable(),
    clientCreatedAt: z.number(),
  }),
  partitionKey: "organizationId",
  handler: (ctx, args) => {
    if (!ctx.auth.userId || !ctx.auth.tenantId || ctx.auth.tenantId !== args.organizationId) {
      throw new CdbError({
        code: "CDB_FORBIDDEN",
        message: "active organization does not match the routed partition",
      });
    }
    ctx.db.insert(messages).values({
      id: args.id,
      body: args.body,
      attachment: args.attachment,
      createdAt: args.clientCreatedAt,
    }).run();
    return { id: args.id };
  },
});

export const replaceMessageAttachment = api.mutation({
  ref: "messages#replaceAttachment",
  authority: "organization",
  args: z.object({
    id: z.string(),
    organizationId: z.string(),
    attachment: z.string().min(1).max(128).transform(FileId),
  }),
  partitionKey: "organizationId",
  handler: (ctx, args) => {
    if (!ctx.auth.userId || !ctx.auth.tenantId || ctx.auth.tenantId !== args.organizationId) {
      throw new CdbError({
        code: "CDB_FORBIDDEN",
        message: "active organization does not match the routed partition",
      });
    }
    ctx.db.update(messages)
      .set({ attachment: args.attachment })
      .where(and(eq(messages.id, args.id), eq(messages.organizationId, args.organizationId)))
      .run();
    return { id: args.id };
  },
});
