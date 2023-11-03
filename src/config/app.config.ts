export const ENV_CONFIG = () => ({
  dbPassword: process.env.DB_PASSWORD,
  dbName: process.env.DB_NAME,
  dbPort: process.env.DB_PORT,
  dbHost: process.env.DB_HOST,
  dbUsername: process.env.DB_USERNAME,

  redisHost: process.env.REDIS_HOST,
  redisUrl: process.env.REDIS_URL,
  redisPort: process.env.REDIS_PORT,
  redisPassword: process.env.REDIS_PASSWORD,

  port: process.env.PORT,
  state: process.env.STATE,
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN,
});
