export class AsyncTaskQueue {
  private active = 0;
  private readonly queue: Array<() => Promise<void>> = [];
  private nextStartAt = 0;

  constructor(
    private readonly concurrency = 1,
    private readonly minStartIntervalMs = 1000,
  ) {}

  enqueue(task: () => Promise<void>): void {
    this.queue.push(task);
    this.drain();
  }

  private drain(): void {
    if (this.active >= this.concurrency || this.queue.length === 0) {
      return;
    }

    const now = Date.now();
    if (now < this.nextStartAt) {
      setTimeout(() => this.drain(), this.nextStartAt - now);
      return;
    }

    while (this.active < this.concurrency && this.queue.length > 0 && Date.now() >= this.nextStartAt) {
      const task = this.queue.shift();
      if (!task) {
        return;
      }

      this.active += 1;
      this.nextStartAt = Date.now() + this.minStartIntervalMs;
      task()
        .catch(() => undefined)
        .finally(() => {
          this.active -= 1;
          this.drain();
        });
    }
  }
}
