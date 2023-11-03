import * as Joi from 'joi';

export const JoiValidationSchema = Joi.object({
  DB_PASSWORD: Joi.string().required(),
  DB_NAME: Joi.string().required(),
  DB_PORT: Joi.string().required(),
  DB_HOST: Joi.string().required(),
  DB_USERNAME: Joi.string().required(),

  REDIS_URL: Joi.string().required(),
  REDIS_HOST: Joi.string().required(),

  PORT: Joi.number().default(3000),
  JWT_SECRET: Joi.string().required(),
  STATE: Joi.string().default('dev'),
});
