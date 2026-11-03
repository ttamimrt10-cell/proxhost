TAMIM FILE HOST - UPDATED RENDER DEPLOYMENT

FILES
- app.py: Original TAMIM File Host bot logic, retained, with Flask /health endpoint
  and an optional background self-ping thread.
- Dockerfile: Installs requirements.txt, Node.js/npm, creates writable runtime folders,
  and runs the application as a non-root user.
- requirements.txt: Python dependencies used by app.py.
- render.yaml: Render Docker Web Service configuration and environment variable names.
- .env.example: Safe placeholders for local development. It contains no real bot token.
- .gitignore: Excludes secrets, databases, uploaded files, logs and Python cache.

RENDER SETUP
1. Upload these project files to a GitHub repository.
2. In Render, create a Blueprint from that repository, or create a Docker Web Service.
3. Set these Environment variables in Render:
   BOT_TOKEN, OWNER_ID, ADMIN_ID, YOUR_USERNAME, UPDATE_CHANNEL.
4. Add Binance variables only if Binance Pay is used:
   BINANCE_API_KEY, BINANCE_SECRET_KEY, BINANCE_PAY_ID.
5. Deploy. Render's health check uses /health.

SELF-PING
- KEEP_ALIVE_ENABLED=true enables the self-ping worker when RENDER_EXTERNAL_URL exists.
- KEEP_ALIVE_INITIAL_DELAY=60 means wait 60 seconds before the first request.
- KEEP_ALIVE_INTERVAL=600 means request /health every 10 minutes.
- The self-ping is best-effort. It does NOT guarantee permanent uptime and may not
  prevent a Render Free service from sleeping. Render can restart services at any time.
- /health is a health-check endpoint; it is separate from the self-ping mechanism.

IMPORTANT SECURITY
- The previously uploaded .env.example contained a real-looking BOT_TOKEN value.
  This updated file replaces it with a placeholder. If that token was real, revoke it
  through Telegram's BotFather and generate a new token before deploying.
- Never commit .env or share a ZIP containing real credentials.

IMPORTANT DATA NOTE
Render Free service filesystems are ephemeral. SQLite data, uploaded scripts, and
runtime-installed packages can be lost after restart/redeploy. Use persistent storage
or an external database/storage service if this data must survive deployments.


AUTOMATIC JSON BACKUP / RECOVERY
- On startup, the app creates config.json and user.json automatically.
- config.json contains admin IDs, admin/control settings, plans and free plans.
- user.json contains user profiles, points, referrals, transactions, subscriptions,
  uploaded-file metadata, pending payments and used transaction IDs.
- Snapshots are refreshed every JSON_BACKUP_INTERVAL seconds (default 60), and
  once more during graceful shutdown. Writes use temporary files + atomic replace.
- If the SQLite database is missing on a fresh start, the app attempts to restore
  the saved JSON snapshots into a newly created database. Existing SQLite data is
  never overwritten by JSON snapshots.
- These JSON files do not contain BOT_TOKEN or Binance secret keys. Keep them private.
- JSON snapshots store uploaded-file metadata, not the actual uploaded script bytes.
  The upload_bots directory must also be backed up separately.

IMPORTANT RECOVERY LIMITATION
Render Free's filesystem is ephemeral. JSON files written inside the service can
be lost along with SQLite and uploaded scripts during redeploy/restart. For reliable
recovery, attach persistent storage where supported or copy backups to an external
private storage/database. Do not commit config.json or user.json to a public GitHub repo.
