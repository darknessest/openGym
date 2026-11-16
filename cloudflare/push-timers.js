import { DurableObject } from 'cloudflare:workers';
import { scheduleAlarm } from './alarms.js';

// This independent alarm wakes push processing without waiting for media cleanup.
export class PushTimers extends DurableObject {
  async schedule(at) {
    if (!Number.isFinite(at) || at < 0) throw new TypeError('invalid push deadline');
    await scheduleAlarm(this.ctx, at);
  }

  async alarm() {
    try {
      await this.env.GYM.get(this.env.GYM.idFromName('personal')).firePushTimers();
    } catch (error) {
      await scheduleAlarm(this.ctx, Date.now() + 10000);
      throw error;
    }
  }
}
