# SeqPass Pi adapter

Uses `pi.registerTool()` for the model-facing bridge and `ctx.ui.custom()`
for the native protected input component. Falls back to trusted external
fulfillment when `ctx.hasUI` is false or the custom UI is unavailable.

Status: scaffold. Requires actual Pi installation to complete and qualify.
See plan section 5.
