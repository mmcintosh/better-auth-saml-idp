// samlify has no "exports" map; its root re-exports from this internal module. Tests only.
declare module "samlify/build/src/api" {
  export function getContext(): { validate?: (xml: string) => Promise<unknown> };
}
