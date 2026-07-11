import { useEffect, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useAppStore } from "./store";
import { OidcCallbackHandler } from "./OidcCallbackHandler";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      refetchOnWindowFocus: false,
    },
  },
});

/** Keeps <html data-theme / data-density> in sync with the store (Dark SOC default). */
function ThemeSync({ children }: { children: ReactNode }) {
  const theme = useAppStore((s) => s.theme);
  const density = useAppStore((s) => s.density);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.setAttribute("data-density", density);
  }, [theme, density]);

  return children;
}

export function Providers({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeSync>
        <OidcCallbackHandler>{children}</OidcCallbackHandler>
      </ThemeSync>
    </QueryClientProvider>
  );
}
