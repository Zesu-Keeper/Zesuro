// Lets the test scripts import the app's TypeScript files (which import each other without
// file extensions). Use:  node --import ./scripts/ts-resolve.mjs scripts/<test>.mjs
import { register } from "node:module";
register("./ts-hooks.mjs", import.meta.url);
