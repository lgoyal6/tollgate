import { createApp } from "vue";
import App from "./App.vue";

createApp(App, { mountPath: window.__TOLLGATE_MOUNT__ }).mount("#app");
