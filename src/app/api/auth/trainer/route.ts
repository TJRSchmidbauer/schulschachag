import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { createSession, isSafeCodeInput, scryptVerify } from '@/lib/auth';

// Datenschutzfreundliches Rate-Limit: Der Zähler liegt nur im Speicher der
// laufenden App (kein Fingerprint, keine IP, kein Protokoll). Nach einem
// Neustart ist die Sperre wieder aufgehoben.
const MAX_FAILS = 5;
const BLOCK_MS = 15 * 60 * 1000;
let failedAttempts = 0;
let blockedUntil = 0;

export async function POST(req: Request) {
  const hash = process.env.TRAINER_CODE_HASH;
  if (!hash) {
    console.error('[trainer-login] TRAINER_CODE_HASH ist nicht gesetzt');
    return NextResponse.json({ error: 'Trainer login nicht konfiguriert' }, { status: 503 });
  }

  if (Date.now() < blockedUntil) {
    return NextResponse.json({ error: 'Zu viele Fehlversuche. Bitte später erneut probieren.' }, { status: 429 });
  }

  const { code } = (await req.json()) as { code?: string };
  // Formatprüfung vor der Hash-Prüfung: blockt Schadcode und Riesen-Eingaben.
  const trimmedCode = isSafeCodeInput(code) ? code.trim() : '';
  if (!trimmedCode) {
    return NextResponse.json({ error: 'Code fehlt' }, { status: 400 });
  }

  const ok = scryptVerify(trimmedCode, hash);
  if (!ok) {
    failedAttempts += 1;
    if (failedAttempts >= MAX_FAILS) {
      blockedUntil = Date.now() + BLOCK_MS;
      failedAttempts = 0;
    }
    return NextResponse.json({ error: 'Ungültig' }, { status: 401 });
  }
  failedAttempts = 0;

  let trainer = await db.user.findFirst({ where: { role: 'TRAINER' } });
  trainer ??= await db.user.create({
    data: {
      alias: 'Trainer',
      role: 'TRAINER',
      codeLookup: 'TRAINER',
      codeHash: hash,
    },
  });
  await createSession(trainer.id, 'TRAINER');
  return NextResponse.json({ ok: true });
}
