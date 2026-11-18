# RadioConnect — testdatabase installeren

**Uitsluitend voor de afzonderlijke Cloudflare D1-testdatabase**
`455e49e5-a229-4d3b-bb0b-0c5da14092c9`.

## Eenmalige installatie

1. Open Cloudflare Dashboard → Storage & databases → D1.
2. Selecteer de **nieuwe testdatabase** op basis van het ID hierboven. Controleer het ID vóór uitvoering.
3. Open de SQL Console.
4. Kopieer de inhoud van [develop_setup_all.sql](./develop_setup_all.sql) naar de console en voer die uit. Dit bestand maakt de tabellen in afhankelijkheidsvolgorde aan.
5. Controleer met:

```sql
SELECT name FROM sqlite_master
WHERE type='table' AND name NOT LIKE 'sqlite_%'
ORDER BY name;
```

Verwacht minimaal: users, stations, station_members, rooms, credentials, sessions, login_attempts, station_invitations, chat_messages, dj_profiles, station_audit_log, direct_messages, chat_message_reactions, chat_message_pins, user_notifications.

**Let op:** `CREATE TABLE IF NOT EXISTS` vervangt geen bestaande tabelstructuren. Gebruik deze bundel voor de nieuwe/lege ontwikkel-database. Bestaande accounts en data uit productie worden **niet** gekopieerd. Controleer na de installatie of de Cloudflare preview-deployment werkelijk de afzonderlijke D1-binding gebruikt; alleen een GitHub-configuratiewijziging is nog geen bevestiging van de actieve binding. Draai dit bestand nooit op de productiedatabase.
