import { beforeAll } from 'vitest';

beforeAll(() => {
  // Ensure document.body exists
  if (!document.body) {
    document.body = document.createElement('body');
  }
});
