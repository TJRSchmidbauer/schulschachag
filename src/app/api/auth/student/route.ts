import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { codeLookupHash, createSession, isSafeCodeInput, isStudentCodeFormat, scryptVerify } from '@/lib/auth';

export async function POST(req: Request) {
  const { code } = (await req.json()) as { code?: string };
  // Formatprüfung vor jeglicher Datenbankabfrage: blockt Schadcode und Riesen-Eingaben.
  if (!isSafeCodeInput(code) || !isStudentCodeFormat(code)) {
    return NextResponse.json({ error: 'Ungültig' }, { status: 400 });
  }
  const lookup = codeLookupHash(code);
  const user = await db.user.findUnique({ where: { codeLookup: lookup } });
  if (!user || !user.active || user.role !== 'STUDENT' || !scryptVerify(code.toUpperCase().trim(), user.codeHash)) {
    return NextResponse.json({ error: 'Ungültig' }, { status: 401 });
  }
  await db.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
  await db.session.deleteMany({ where: { userId: user.id } });
  await createSession(user.id, 'STUDENT');
  return NextResponse.json({ alias: user.alias });
}
