/// <reference types="vite/client" />

declare global {
  interface Window {
    __TOLLGATE_MOUNT__: string;
  }
}

export {};
