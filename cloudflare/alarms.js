const pending = new WeakMap();

// An object's subsystems share one alarm. Serialize read/compare/write so a later deadline
// cannot overwrite an earlier wakeup while both callers await the storage API.
export async function scheduleAlarm(ctx, at) {
  const previous = pending.get(ctx) || Promise.resolve();
  const next = previous.catch(() => {}).then(async () => {
    const alarm = await ctx.storage.getAlarm();
    if (alarm == null || alarm > at) await ctx.storage.setAlarm(at);
  });
  pending.set(ctx, next);
  try { await next; }
  finally { if (pending.get(ctx) === next) pending.delete(ctx); }
}
