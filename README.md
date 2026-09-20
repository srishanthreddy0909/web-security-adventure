# Web Security Adventure — Production Build

Dark, game-first web security investigation lab built with Flask. Designed for local terminal testing and Vercel deployment.

## Local run

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open `http://127.0.0.1:5000`.

Without `DATABASE_URL`, local development uses SQLite (`adventure.db`).

## Vercel deployment

Vercel now supports Flask directly through its Python runtime, so this project does not need a custom `/api` wrapper. See Vercel's current Flask example: https://vercel.com/templates/python/flask-python-boilerplate

For production, set these Vercel environment variables:

```text
GAME_SECRET=<long-random-secret>
DATABASE_URL=<managed-postgresql-connection-string>
GAME_COMPANY=<your chosen fictional company name>
ADMIN1_ID=<private admin 1 id>
ADMIN1_PASSWORD=<private admin 1 password>
ADMIN2_ID=<private admin 2 id>
ADMIN2_PASSWORD=<private admin 2 password>
```

Do **not** use SQLite for the public Vercel deployment. Vercel deployments are immutable/read-only at runtime, so persistent player data belongs in a hosted database.

## Admin

Private route:

`/ops-room-7c4f`

Only the two configured admin credentials can enter the admin area. The admin route is not linked from the player UI and authorization is checked server-side.

Admin dashboard includes:
- live score ranking
- player rank
- XP totals
- mission completion bars
- hints used
- participant progress
- recent activity
- organizer-only reset

## Event behavior

- 10 missions
- funny flags
- DevTools investigation
- controlled SQLi/XSS/CSRF simulations
- Mission 10 Burp Suite workflow
- player accounts and progress
- top-10 player leaderboard

## Important scaling note

The app uses small Flask requests and a hosted PostgreSQL database for production. This is appropriate for the intended 200–300 participant event architecture, but no platform can honestly guarantee zero latency under every network condition. Test with a realistic group before the event.
