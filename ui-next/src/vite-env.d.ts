/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AEGIS_DEMO_MODE?: string;
  readonly VITE_AEGIS_GATEWAY_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
