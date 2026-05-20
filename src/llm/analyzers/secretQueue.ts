export class AsyncTaskQueue {
  private active = 0;
  private readonly queue: Array<() => Promise<void>> = [];

  constructor(private readonly concurrency = 2) {}

  enqueue(task: () => Promise<void>): void {
    this.queue.push(task);
    this.drain();
  }

  private drain(): void {
    while (this.active < this.concurrency && this.queue.length > 0) {
      const task = this.queue.shift();
      if (!task) {
        return;
      }

      this.active += 1;
      task()
        .catch(() => undefined)
        .finally(() => {
          this.active -= 1;
          this.drain();
        });
    }
  }
}
