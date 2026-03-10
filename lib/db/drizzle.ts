import { neon } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-http';
import * as schema from './schema';
import dotenv from 'dotenv';

dotenv.config();

if (!process.env.POSTGRES_URL) {
  throw new Error('POSTGRES_URL environment variable is not set');
}

// Neon serverless driver — works in Edge (middleware) and Node.js
const sql = neon(process.env.POSTGRES_URL);
export const db = drizzle(sql, { schema });
