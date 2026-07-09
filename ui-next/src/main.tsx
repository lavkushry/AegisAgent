import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Providers } from "@/app/providers";
import { AppRouter } from "@/app/router";
import "./index.css";

const root = document.getElementById("root");
if (!root) {
  throw new Error("root element missing");
}

createRoot(root).render(
  <StrictMode>
    <Providers>
      <AppRouter />
    </Providers>
  </StrictMode>,
);
