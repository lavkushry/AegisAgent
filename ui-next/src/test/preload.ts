/**
 * Bun test preload — provides a minimal browser DOM for CSRF / UI tests.
 * Registered via bunfig.toml [test].preload.
 */
import { Window } from "happy-dom";

const window = new Window({ url: "http://127.0.0.1:3000/dashboard/" });

// Expose globals expected by browser code under test.
Object.assign(globalThis, {
  window,
  document: window.document,
  HTMLElement: window.HTMLElement,
  customElements: window.customElements,
  Element: window.Element,
  Node: window.Node,
  navigator: window.navigator,
  location: window.location,
  localStorage: window.localStorage,
  sessionStorage: window.sessionStorage,
});
