import React from "react";
import ReactDOM from "react-dom/client";
import { Toaster } from "sonner";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import { installFrontendDiagnostics } from "./lib/diagnostics";
import "./index.css";
import "sonner/dist/styles.css";
installFrontendDiagnostics();
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
      <Toaster
        position="bottom-right"
        theme="dark"
        closeButton
        offset={12}
        visibleToasts={3}
        toastOptions={{
          style: {
            fontSize: "12px",
            maxWidth: "min(340px, calc(100vw - 24px))",
          },
        }}
      />
    </ErrorBoundary>
  </React.StrictMode>,
);
