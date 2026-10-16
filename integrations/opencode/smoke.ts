// Smoke test: verify plugin module exports resolve and types compile.
import { id, tui } from "./index";
if (typeof id !== "string") throw new Error("id must be string");
if (typeof tui !== "function") throw new Error("tui must be function");
console.log("smoke: id=" + id + " tui=" + typeof tui);
