import { sql } from 'drizzle-orm';
import { db } from './client';

export async function withTenant<T>(tenantId: string, fn: () => Promise<T>) {
  await db.execute(sql`SET app.tenant_id = ${tenantId}`);
  return fn();
}
