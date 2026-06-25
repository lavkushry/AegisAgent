"use client";

import React, { useEffect, useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useAppStore } from "./store";

export default function Providers({ children }: { children: React.ReactNode }) {
  const theme = useAppStore((s) => s.theme);
  const density = useAppStore((s) => s.density);

  // Sync persisted preferences onto <html> on mount, since the server
  // rendered the default and localStorage may hold a different choice.
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.setAttribute("data-density", density);
  }, [theme, density]);

  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            refetchOnWindowFocus: false,
            retry: 1,
            staleTime: 5000,
          },
        },
      })
  );

  return (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
}
