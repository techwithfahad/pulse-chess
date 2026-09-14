<div align="center">
  <img src="assets/logo.png" alt="Pulse Chess" width="480">

  <p><strong>Real-time multiplayer chess, built from scratch for the web.</strong></p>

  <p>
    <img src="https://img.shields.io/badge/JavaScript-ES6%2B-F7DF1E?logo=javascript&logoColor=black" alt="JavaScript ES6+">
    <img src="https://img.shields.io/badge/Node.js-Express-339933?logo=nodedotjs&logoColor=white" alt="Node.js and Express">
    <img src="https://img.shields.io/badge/Socket.IO-Realtime-010101?logo=socketdotio&logoColor=white" alt="Socket.IO">
    <img src="https://img.shields.io/badge/PostgreSQL-Database-4169E1?logo=postgresql&logoColor=white" alt="PostgreSQL">
  </p>

  <p>
    <a href="https://pulse-chess.onrender.com/">
      <img src="https://img.shields.io/badge/Play_Pulse_Chess-Live_Demo-D8FF63?style=for-the-badge&labelColor=181A1B" alt="Play Pulse Chess live">
    </a>
  </p>
</div>

## Overview

Pulse Chess is a full-stack, real-time browser chess platform built from scratch as a portfolio project. It combines live player-versus-player games, ranked matchmaking, private rooms, practice bots, persistent game history, and post-game analysis in one responsive web application.

The project was designed to demonstrate practical software-engineering skills beyond a static interface: real-time event handling, server-authoritative game logic, relational data modeling, authentication, API integrations, security controls, and production deployment.

## What I built

- Real-time multiplayer chess with Socket.IO and server-side move validation
- Ranked matchmaking, private rooms, clocks, increments, rematches, and reconnect handling
- Stockfish-powered practice bots and post-game position review
- PostgreSQL-backed accounts, ratings, match history, friendships, direct messages, and notifications
- Email verification through Brevo and Google sign-in
- A responsive dark interface with SVG chess pieces, board themes, animations, and mobile support

## Technology

- **Frontend:** HTML, CSS, vanilla JavaScript, SVG
- **Backend:** Node.js, Express, Socket.IO
- **Data and chess:** PostgreSQL, `pg`, `chess.js`, Stockfish 18
- **Authentication and security:** Argon2, server-side sessions, Helmet, rate limiting, input validation, profanity filtering, and parameterized SQL queries
- **Deployment:** Render

## Demo

The final interface is designed around a clean, dark chess experience. The animations below are included in `assets/demo/` so GitHub renders them directly in the repository README.

### Home

![Pulse Chess home](assets/demo/home.gif)

### Matchmaking

![Pulse Chess matchmaking](assets/demo/matchmaking.gif)

### Leaderboards

![Pulse Chess leaderboards](assets/demo/leaderboards.gif)

### Game result

![Pulse Chess win result](assets/demo/win-result.gif)

## Features

### Chess

- Server-authoritative legal moves, clocks, FEN synchronization, and game results
- Rated quick matchmaking and private rooms with six-character codes
- Six time controls: 1+0, 3+0, 3+2, 5+0, 10+0, and 15+10
- Play Bot practice ladder from Beginner 500 to Elite 3000
- Same-bot rematches with the original difficulty and clock settings
- Draw offers, resignation, reconnect handling, and live game chat
- Thirty-second reconnect window; a second disconnect forfeits the game
- PGN export, FEN copying, stored match history, and final-board viewing
- Stockfish post-game review with Best, Excellent, Good, Inaccuracy, Mistake, and Blunder classifications
- Private spectating for accepted friends

Bot ratings are practice targets, not certified FIDE ratings. Bot games do not affect ranked ratings.

### Accounts and community

- Email/password accounts with Argon2 password hashing
- Six-digit email verification through Brevo
- Google sign-in and secure server-side sessions
- Player search, profiles, avatars, bios, flags, ratings, and presence
- Friend requests, persistent direct messages, notifications, blocking, and reporting
- Username cooldowns and profanity/evasion filtering
- Leaderboard page with ranking filters and the completed leaderboard animation section
- Recent matches and detailed stored game views

### Interface and media

- Dark responsive interface with no CSS gradients
- SVG chess pieces and seven board themes
- Responsive desktop and mobile layouts
- Win, loss, draw, matchmaking, verification, and review states
- Four supplied GIF animation assets in `assets/demo/`, including the leaderboard and victory animations
- Terms, Privacy, Cookies, and Fair Play pages

## Run locally

Create a `.env` file and never commit it:

```env
DATABASE_URL=your_postgresql_connection_string
DATABASE_URL_POOLED=your_pooled_postgresql_connection_string
SESSION_SECRET=at_least_32_random_characters
BREVO_API_KEY=your_brevo_api_key
```

Install and start:

```powershell
npm.cmd install
npm.cmd start
```

Open `http://localhost:3000`.

Run checks with `npm.cmd run check`.

## Email verification

The Brevo sender must be authorized as `noreply.pulsechess@gmail.com`. Signup stores a pending verification record and sends a six-digit code. The code expires after ten minutes, and the account is not activated until verification succeeds.

## Deployment

Use a persistent PostgreSQL database, set production environment variables in the host dashboard, use `npm start`, deploy the complete project root, and include the complete `assets/` directory. Never upload `.env` or expose API keys.

## Fair play

Built-in bots and post-game review are allowed. Outside engines, automation, move assistance, exploits, or another person are not allowed during rated player-versus-player games.

---

<div align="center">
  Built by <a href="https://github.com/techwithfahad">Fahad Khan</a>
</div>