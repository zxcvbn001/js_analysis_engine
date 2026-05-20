import { buildServer } from './api/server.js';
import { getConfig } from './config/appConfig.js';

const config = getConfig();
const { port, host } = config.server;

const app = await buildServer(config);

try {
  await app.listen({ port, host });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
