import { neon } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-http';
import * as schema from './schema';
import dotenv from 'dotenv';

dotenv.config();

// Lazy database initialization to avoid build-time errors
let dbInstance: ReturnType<typeof drizzle> | null = null;

function initDb() {
  if (!process.env.POSTGRES_URL) {
    throw new Error('POSTGRES_URL environment variable is not set');
  }
  
  if (!dbInstance) {
    const sql = neon(process.env.POSTGRES_URL);
    dbInstance = drizzle(sql, { schema });
  }
  
  return dbInstance;
}

// Export a proxy that initializes on first access
export const db = new Proxy({} as ReturnType<typeof drizzle>, {
  get(target, prop) {
    const instance = initDb();
    return (instance as any)[prop];
  }
});
