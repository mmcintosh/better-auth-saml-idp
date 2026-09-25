declare module "*.wasm" {
  const mod: WebAssembly.Module;
  export default mod;
}
declare module "#xsd-wasm" {
  export function loadXsdWasm(): Promise<WebAssembly.Module | Uint8Array>;
}
