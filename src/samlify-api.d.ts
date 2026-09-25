// samlify has no "exports" map; this internal module is the one its root re-exports from.
declare module "samlify/build/src/api" {
  export function getContext(): { validate?: (xml: string) => Promise<unknown> };
}
