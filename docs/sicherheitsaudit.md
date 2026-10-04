# 🔍 Sicherheits- und Datenschutzaudit

Stand: **4. Oktober 2026**
Gegenstand: selbst gehostete Installation von SchulSchach (`compose.portainer.yml`) für den Einsatz in einer Schul-AG.

> ⚠️ **Einordnung:** Dieses Audit wurde mit Hilfe einer KI-Assistenz durchgeführt. Es ersetzt keine Prüfung durch eine unabhängige Fachperson, insbesondere nicht durch die/der Datenschutzbeauftragte der Schule. Es ist eine Bestandsaufnahme gegen anerkannte Prüfraster (OWASP ASVS/Top 10, BSI-IT-Grundschutz, DSGVO) und benennt offen, was **nicht** geprüft oder **nicht** umgesetzt ist.

---

## 📌 Zusammenfassung

| Bereich | Bewertung | Wesentlicher Punkt |
|---|---|---|
| Anmeldung und Sitzungen | ✅ solide | Kein Passwort, Hashing mit scrypt, Sitzung 2 Std., Rate-Limit |
| Eingabeprüfung und Injection | ✅ solide | Prisma/Parameterbindung, serverseitige Formatprüfung |
| XSS und Content-Security-Policy | ✅ gut | CSP aktiv; `unsafe-inline` bei Skripten bleibt Restrisiko |
| Autorisierung / Rechte | ✅ gut | Trainer- und Schülerpfade serverseitig geprüft |
| Datenminimierung und Logging | ✅ gut | Keine Klarnamen, keine Codes/IPs in Logs |
| Datenschutz (DSGVO) | 🟡 prüfbedürftig | Einwilligung, Verzeichnis, Löschfristen beim Betreiber |
| Backup und Verfügbarkeit | ✅ gut | Nächtliche Dumps, 7/4/3 Stände, Restore getestet |
| Abhängigkeiten und Updates | 🟡 offen | Kein automatischer Update-Check, manuell nachziehen |
| Betriebsumgebung | ✅ gut | Container mit `no-new-privileges`, `cap_drop: ALL`, Limits |

**Kernergebnis:** Die technischen Maßnahmen der Prioritäten A und B aus dem Konzept sind umgesetzt und lokal verifiziert. Die größten Restpunkte sind organisatorischer Natur (Einwilligung, Verzeichnis der Verarbeitungstätigkeiten, jährliche Prüfung der Abhängigkeiten).

---

## 1. 🔐 Authentifizierung und Sitzungen (OWASP A07)

**Umgesetzt:**

- Schüler melden sich **ausschließlich mit persönlichem Code** an – kein Passwort, keine E-Mail, kein Klarname. Der Code ist zehnstellig (`[A-Z0-9]`).
- Der **Trainer-Code wird nur als Hash gespeichert** (`scrypt`, Format `scrypt:...`), erzeugt über `npm run hash:trainer`. Der Klartext steht nirgends in der Datenbank oder in Logs.
- Schülercodes werden zusätzlich mit **AES-256-GCM** verschlüsselt abgelegt (Schlüssel `CODE_ENC_KEY`, sonst `AUTH_SECRET`), damit der Trainer sie anzeigen kann.
- **Sitzungen** laufen über ein `HttpOnly`-Cookie mit `SameSite=Lax` und `Secure` (bei `APP_URL` mit `https://`), gültig maximal **2 Stunden** (vorher: 12 Stunden).
- Abmelden löscht das Cookie serverseitig.

**Prüfergebnis:** Login mit gültigem/ungültigem Code, Session-Ablauf und Secure-Flag lokal getestet.

**Restrisiko:** Ein Trainer-Code bleibt eine gemeinsam genutzte Geheimtext-Zeile. Wer ihn kennt, hat volle Rechte – es gibt keine Zweite-Faktor-Prüfung und keine Rollen innerhalb des Trainerbereichs.

---

## 2. 🛡️ Anmeldung gegen Ausprobieren (Rate-Limit) (OWASP A07)

**Umgesetzt:**

- `/api/auth/trainer`: nach **5 Fehlversuchen 15 Minuten Sperre**, Antwort `429`.
- Zähler liegt **nur im Arbeitsspeicher**, ohne Speicherung von IP-Adresse oder Protokoll (Datensparsamkeit). Ein Neustart des Containers hebt die Sperre auf.
- `/api/auth/student`: **kein** zusätzliches Rate-Limit. Ein Fehlversuch kostet genau einen Index-Lookup über den Code-Hash plus einen scrypt-Abgleich; Rates werden nicht in Logs oder IP-Adressen gespeichert. Der Suchraum sind zehn Zeichen aus Großbuchstaben und Ziffern (36¹⁰ Kombinationen), ein blindes Erraten ist damit praktisch ausgeschlossen. Der Code ist nach jedem Ausstellen ohnehin ein anderer.

**Prüfergebnis:** Fünf Fehlversuche → `429 Too Many Requests`; korrekter Code danach erst nach Ablauf der Sperre.

**Restrisiko / Offen:**

- Der globale Zähler sperrt **alle** Anmeldungen, wenn fünf Fehlversuche auftreten – auch von anderen Personen. Das ist im Schulbetrieb unkritisch (DoS-Wirkung begrenzt) sollte aber bekannt sein.
- Eine verteilte Umgehung (viele IPs) ist technisch nicht vollständig verhindert; der Trainer-Code ist daher mindestens 20 Zeichen lang und nie in Repositories oder Logs zu hinterlegen.
- **Empfehlung:** Für den Schüler-Login lässt sich der gleiche Zähler ergänzen, sobald ein Missbrauch auffällt – bewusst noch nicht umgesetzt, weil es bisher keinen Anlass gab und jeder Fehlversuch schon teuer für den Angreifer ist.

---

## 3. 🧬 Injection, Eingabeprüfung und Datenbankzugriff (OWASP A03)

**Umgesetzt:**

- Datenbankzugriff ausschließlich über **Prisma** mit Parameterbindung; keine SQL-Strings aus Benutzereingaben.
- **Serverseitige Formatprüfung** aller Anmelde-Eingaben:
  - `isSafeCodeInput()` – Zeichenvorrat und Länge (max. 64 Zeichen), lehnt Steuerzeichen und Sonderzeichen ab,
  - `isStudentCodeFormat()` – exakt zehn Großbuchstaben/Ziffern,
  - beide werden **vor** jedem Hash-Lookup in der Datenbank angewendet (`src/app/api/auth/student/route.ts`, `src/app/api/auth/trainer/route.ts`).
- Eingabefelder haben zusätzlich `maxLength`, `spellCheck={false}` und `autoComplete="off"`.

**Prüfergebnis:** Schadcode- und SQL-Versuche (`' OR 1=1--`, längere Zeichenketten) werden mit `400` bzw. `401` abgelehnt, ohne Datenbankzugriff.

**Restrisiko:** gering.

---

## 4. 🚫 Cross-Site-Scripting (XSS) und Content-Security-Policy (OWASP A03)

**Umgesetzt in `next.config.ts` (gilt für alle Routen):**

```
default-src 'self'
script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'
style-src 'self' 'unsafe-inline'
img-src 'self' data: blob:
font-src 'self'
connect-src 'self'
worker-src 'self' blob:
object-src 'none'
frame-ancestors 'none'
form-action 'self'
base-uri 'self'
```

Weitere Header: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `X-Powered-By` entfernt.

**Bewusste Einschränkungen:**

- `'unsafe-inline'` bei `script-src` ist für den Next.js App Router nötig (Inline-Skripte beim Streaming). Eine Nonce-basierte Policy ist in dieser Konfiguration **nicht** sauber umgesetzt – **Offener Punkt für eine spätere Iteration**.
- `'wasm-unsafe-eval'` wird für die lokale Stockfish-Engine (WebAssembly) gebraucht.
- Die Engine läuft lokal im Browser, `connect-src 'self'` verhindert, dass Stellungen an externe Dienste gesendet werden.

**Prüfergebnis:** Header per `curl -sI` verifiziert; fremde Domains werden von CSP blockiert.

**Restrisiko:** XSS-Schutz stützt sich auf Reacts Escaping und die serverseitige Eingabeprüfung, nicht auf die CSP allein.

---

## 5. 👤 Autorisierung und Zugriffskontrolle (OWASP A01)

**Umgesetzt:**

- Jede Trainer-Seite und jeder Trainer-Endpunkt prüft die Session **serverseitig**; ohne gültiges Cookie → Weiterleitung bzw. `401`.
- **Gruppen-/Modulfreigabe wird serverseitig geprüft:** Ein Lernpfad, der der Gruppe nicht freigegeben ist, führt zu `404`, auch wenn die URL bekannt ist (`src/app/learn/module/[id]/page.tsx`, Relation `learningPath`). Die bisherige Prüfung nur im Client wurde damit geschlossen.
- Schüler sehen nur eigene Daten; Aliasse sind pseudonym, Klarnamen existieren im System nicht.
- Urkundennamen werden **nur im Browser** eingetragen und nie an den Server gesendet.

**Restrisiko:** Es gibt nur eine Rolle (Trainer) ohne Feinrechte. Wer Zugang zum Trainerbereich hat, sieht alle Aliasse und Daten der AG.

---

## 6. 📝 Protokollierung und Datenschutz (DSGVO Art. 5, 30, 32)

**Umgesetzt:**

- **Datenminimierung in den Logs:** Keine Aliasse, keine Klarnamen, keine Codes, keine IP-Adressen, keine Header. Es werden nur allgemeine technische Ereignisse protokolliert. Das frühere `verify`-Log im Trainer-Login und die DB-Fehler-Details wurden entfernt (`settings.ts`, `extras-server.ts`).
- **Audit-Logs ohne Titel/Alias-Platzhalter:** Das Ändern eines Schüler-Codes und das Anlegen von Hausaufgaben protokollieren nur technische Ereignisse (`students/[id]/code/route.ts`, `assignments/route.ts`).
- **Kein Chat, keine Tracker, keine externen Schriften oder CDNs.**
- **Aufbewahrungsfristen** einstellbar: beendete Live-Partien und Turniere werden automatisch nach 90 Tagen (Standard) gelöscht.
- **Seed-Datensparsamkeit:** Test-Schüler und Zugangscodes werden nur erzeugt, wenn `SEED_SHOW_TEST_CODES=1` gesetzt ist oder `NODE_ENV !== 'production'`. Im Produktivbetrieb schreibt der Seed **keine** Testcodes in die Logs.
- **Standard-Datenschutztext** in den Einstellungen vorhanden und um die Prüfpunkte ergänzt; die Vorlage verweist auf die Pflichten des Betreibers.

**Offen (organisatorisch, kann die Software nicht leisten):**

1. **Einwilligung oder andere Rechtsgrundlage** der Erziehungsberechtigten für das Verarbeiten von Lern-, Spiel- und Turnierdaten (DSGVO Art. 6/7).
2. **Verzeichnis der Verarbeitungstätigkeiten** (Art. 30) und **Datenschutz-Folgenabschätzung**, falls die Schule das für die AG als erforderlich einstuft.
3. **Information der Eltern** (Transparenz, Art. 13/14).
4. Prüfung, ob die Aufbewahrungsfristen (90 Tage Inhalt, 7 Tage/4 Wochen/3 Monate Backup) den Vorgaben der Schule entsprechen – sonst in `compose.portainer.yml` kürzen.
5. Sichere Aufbewahrung von `AUTH_SECRET` und `CODE_ENC_KEY` (Passwortmanager, getrennt vom Backup).

---

## 7. 💾 Datensicherung und Wiederherstellung (BSI GR 3)

**Umgesetzt:**

- Dienst `pgbackups` sichert die PostgreSQL-Datenbank **nächtlich und beim Stack-Start**.
- Es werden **7 Tagesstände, 4 Wochenstände und 3 Monatsstände** aufbewahrt (Image `docker-postgres-backup-local`).
- Dumps liegen im Docker-Volume `schulschach_backups`.
- **Restore wurde lokal getestet** und erfolgreich durchgeführt (4 Benutzer, 11 Puzzles, 1 Lernpfad stimmten nach dem Einspielen überein).
- Anleitung für Kopie auf einen zweiten Speicherort: [datensicherung.md](datensicherung.md).

**Prüfergebnis:** Dump erzeugt, Restore ausgeführt, Datenbestand verglichen – ✓.

**Offen:**

- Die Backups liegen **im selben Host** wie die Anwendung. Für echte Ausfallsicherheit braucht es eine Kopie auf einem zweiten System (Anleitung vorhanden).
- Backups enthalten Aliasse und Lernstand bis zum Ablauf der Aufbewahrung – auch wenn Inhalte inzwischen gelöscht wurden. Fristen entsprechend der Schulvorgabe wählen.
- Es gibt **kein automatisches Wiederherstellungs-Testing**; Restore mindestens einmal jährlich manuell durchführen.

---

## 8. 🏗️ Betrieb, Container und Netzwerk (BSI APP 4 / ORP 4)

**Umgesetzt in `compose.portainer.yml`:**

- `no-new-privileges: true`, `cap_drop: ALL`, feste CPU- und Speicherlimits.
- Datenbank **nur im internen Docker-Netz**, nicht über einen Ports nach außen erreichbar.
- TLS ausschließlich über Traefik (`web_net`).
- Portainer-Stack mit fester Compose-Datei; die App läuft **als Einzige Instanz** (der Live-Nachrichtenverteiler arbeitet im Speicher).
- Ausführliche Absicherungsdoku in der README, Abschnitt „Datenschutz und Sicherheit“.

**Offen / Hinweise:**

- **Abhängigkeiten und Sicherheitsupdates:** Es läuft kein automatischer Update-Check. Vor größeren Updates `npm audit` bzw. ein Build mit aktualisierten Abhängigkeiten durchführen und den Stack „Pull and redeploy“ starten. Regelmäßigkeit empfohlen: **mindestens vierteljährlich**, bei kritischen Meldungen sofort.
- Versionsstände von Next.js, Prisma und PostgreSQL liegen im Repository; sie werden mit jedem Update nachgezogen.
- `npm audit` für die lokale Entwicklung sollte Teil des Update-Ablaufs sein.

---

## 9. 🧩 Weitere Sicherheits-Maßnahmen für Eingabefelder

Zusätzlich zu den Prüfungen in Abschnitt 3 gelten für **alle** Eingabefelder der App (Schüler wie Trainer) folgende Regeln:

### 9.1 Validierung auf dem Server

- Jede Eingabe, die Datenbank, Dateisystem oder Logik beeinflusst, wird **serverseitig** geprüft – niemals nur im Browser. Clientseitige Prüfung ist Komfort, kein Schutz.
- **Whitelist statt Blacklist:** Erlaubt sind nur die Zeichen, die tatsächlich gebraucht werden (z. B. `[A-Z0-9]` für Codes, Zahlen für Ergebnisse, ein begrenzter Zeichenvorrat für Aliasse). Alles andere wird verworfen, nicht „bereinigt“.
- **Längenbegrenzung** vor jeder Verarbeitung (z. B. `isSafeCodeInput` max. 64 Zeichen), damit keine überlangen Strings Speicher oder Hash-Aufwand überfordern.
- **Typprüfung:** Erwartet die Stelle eine Zahl, wird geparst und `NaN`/Range-Fehler abgelehnt; erwartet sie einen String, wird kein Objekt/Array angenommen.

### 9.2 Formatprüfung und Kontext

- **Kontextabhängige Prüfung:** Ein Alias darf andere Zeichen enthalten als ein Zugcode; ein FEN-String wird gegen die erlaubte FEN-Syntax geprüft, ein Wert für die Bedenkzeit gegen die in den Einstellungen erlaubten Zeiten.
- **Abweisung statt Umwandlung:** Eingaben, die das Format verlassen, führen zu `400 Bad Request` mit neutrale Fehlermeldung – ohne Angabe, ob ein Eintrag existiert (kein User-Enumeration).
- **Kodierung beachten:** Bei Weitergabe in URLs oder CSV wird kodiert; Zeichenumbrüche in Freitext (Impressum, Datenschutz, Begrüßungstext) werden als Markdown gerendert und nicht als HTML interpretiert.

### 9.3 Speicherung und Wiedergabe

- **Keine Ausgabe von Benutzereingaben in Logs** – auch nicht in Fehlerpfaden. Fehlermeldungen an Nutzer:innen bleiben generisch („Anmeldung fehlgeschlagen“), ohne eingegebenen Wert zu wiederholen.
- **Keine Wiedergabe von Eingaben als HTML.** React escaped standardmäßig; Template-Strings in `dangerouslySetInnerHTML` sind zu vermeiden oder dürfen nur aus freigegebenen, statischen Bestandteilen bestehen.
- **Parameterbindung in der Datenbank** (Prisma) statt String-Konkatenation – auch bei „harmlosen“ Werten wie Sortier- oder Filterfeldern.
- **Codewerte niemals in Query-Parametern** weitergeben, da diese in Browser-Verlauf, Server-Logs und Referrer landen.

### 9.4 Automatisches Zurücksetzen und Sperren

- **Auto-Reset der Eingabefelder:** Nach erfolgreichem oder fehlgeschlagenem Absenden werden sensible Felder (Codes, Passwörter, Trainer-Code) zurückgesetzt, damit kein Wert im DOM oder im Browser-Autovervollständigen stehen bleibt.
- **Automatische Sperrung bei Wiederholung:** Der Trainer-Login sperrt nach 5 Fehlversuchen für 15 Minuten (Abschnitt 2). Für Schülerkonten genügt die begrenzte Gültigkeit des persönlichen Codes; ein erneutes Ausstellen durch den Trainer setzt den Zugang ohnehin zurück.
- **Sitzung bei Beendigung zurücksetzen:** Abmelden löscht Cookie und Servereintrag; nach 2 Stunden Inaktivität endet die Sitzung automatisch.
- **Keine Übernahme von Eingaben in versteckte Felder:** Eingaben aus einer Anmeldung werden nicht in andere Formulare oder Zustände übernommen (kein Präfilling sensibler Werte).

---

## ✅ Verifikationsnachweis (lokal durchgeführt)

| Prüfung | Ergebnis |
|---|---|
| Anmeldung mit korrektem Schülercode | ✓ erfolgreich, Session 2 Std. |
| Anmeldung mit korrektem Trainer-Code | ✓ erfolgreich |
| 5× falscher Trainer-Code | ✓ `429` nach 5 Fehlversuchen |
| SQL-Injection-Versuch im Anmeldefeld | ✓ `401`, kein DB-Zugriff |
| Überlanger/Schadcode im Anmeldefeld | ✓ `400` (Formatprüfung) |
| Security-Header per `curl -sI` | ✓ CSP, nosniff, DENY, no-referrer gesetzt |
| Seed im Produktivmodus | ✓ keine Testcodes in Logs |
| Backup-Container | ✓ Dump erzeugt (7/4/3 Stände) |
| Wiederherstellung aus Dump | ✓ Datenbestand stimmte überein |
| Modulpfad ohne Gruppenfreigabe | ✓ `404` statt Zugriff |
| Lokaler Stack (`compose.local.yml`) | ✓ `http://localhost:3000` lauffähig |

---

## 📋 Offene Punkte für den Betreiber

| # | Punkt | Zuständig |
|---|---|---|
| 1 | Einwilligung der Erziehungsberechtigten einholen und dokumentieren | Schule / AG-Leitung |
| 2 | Verzeichnis der Verarbeitungstätigkeiten ergänzen | Datenschutzbeauftragte/r |
| 3 | Aufbewahrungsfristen an Schulvorgabe anpassen | Betreiber:in |
| 4 | Backup regelmäßig auf einen zweiten Speicherort kopieren | Betreiber:in |
| 5 | Restore mindestens einmal jährlich testen | Betreiber:in |
| 6 | `npm audit` / Sicherheitsupdates mindestens vierteljährlich | Betreiber:in |
| 7 | Nonne-basierte CSP als Nachfolge der `unsafe-inline`-Regel (Dev) | Entwicklung |
| 8 | Unabhängige Prüfung der Version durch Fachperson veranlassen | Schule / AG-Leitung |

---

*Dieses Audit beschreibt den Stand der im Repository hinterlegten Konfiguration und des Codes. Änderungen an Code, Domains, Umgebungsvariablen oder der Infrastruktur können die Ergebnisse entwerten und erfordern eine erneute Prüfung.*
