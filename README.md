# Workout Tracker API

Version: **0.4.0**

A production-grade REST API for tracking workouts, exercises, and sets. Built with **FastAPI** and **PostgreSQL**, with **migrations** and **tests**.

> Goal: demonstrate real backend engineering practices (clean architecture, validation, auth, testing, documentation, CI).

---

## Features

-   JWT auth with access tokens + refresh tokens (HTTP-only cookie + rotation)
-   User self-service: `GET /users/me`, `POST /users/me/change-password`, `DELETE /users/me`
-   Role support (`user`, `admin`)
-   Workouts with nested workout exercises and sets
-   Exercises catalog (admin-managed) with pagination + filtering
-   Soft delete for exercises (`is_active`)
-   Input validation + consistent error responses
-   PostgreSQL schema with constraints + migrations (Alembic)
-   Automated tests (integration: auth, users, exercises, workouts, workout exercises, sets)
-   OpenAPI docs (Swagger UI)

---

## Tech Stack

-   **Python**: 3.13.3
-   **API**: FastAPI, Pydantic v2
-   **DB**: PostgreSQL
-   **ORM**: SQLAlchemy 2.0
-   **Migrations**: Alembic
-   **Auth**: JWT (access + refresh), pwdlib (Argon2id) password hashing
-   **Tests**: pytest, httpx
-   **Quality**: ruff
-   **Package manager**: uv
-   **Dev**: Docker Compose

---

## Architecture

The project uses a layered structure to keep HTTP concerns separate from business rules and persistence:

-   `app/main.py` - FastAPI initialization
-   `app/routers/` - route definitions
-   `app/schemas/` - Pydantic models (API contract)
-   `app/services/` - business logic (permissions, domain rules)
-   `app/models/` - SQLAlchemy models (DB entities)
-   `app/db/` - session/engine + migrations
-   `app/core/` - configuration and security settings

High-level request flow:

`Router -> Service -> DB Session/Models -> Response Schema`

---

## Data Model (simplified)

-   `users`
-   `exercises`
-   `workouts`
-   `workout_exercises`
-   `sets`

Notes:

-   All user-owned resources are scoped by `user_id`
-   Refresh tokens are stored server-side for rotation and revocation
-   Exercises are global and managed by admins; users can only view active ones

---

## API Overview

Base path: `/v1`

### Auth

-   `POST /v1/auth/register`
-   `POST /v1/auth/login`
-   `POST /v1/auth/refresh`
-   `POST /v1/auth/logout`

### Users

-   `GET /v1/users/me`
-   `POST /v1/users/me/change-password`
-   `DELETE /v1/users/me`

### Exercises

-   `GET /v1/exercises` (supports `name`, `limit`, `offset`)
-   `GET /v1/exercises/{id}`
-   `POST /v1/exercises` (admin)
-   `PATCH /v1/exercises/{id}` (admin)
-   `DELETE /v1/exercises/{id}` (admin, soft delete)

### Workouts

-   `GET /v1/workouts`
-   `GET /v1/workouts/{id}`
-   `POST /v1/workouts`
-   `PATCH /v1/workouts/{id}`
-   `DELETE /v1/workouts/{id}`

### Workout Exercises

-   `GET /v1/workouts/{workout_id}/exercises`
-   `POST /v1/workouts/{workout_id}/exercises`
-   `PATCH /v1/workouts/{workout_id}/exercises/{workout_exercise_id}`
-   `DELETE /v1/workouts/{workout_id}/exercises/{workout_exercise_id}`

### Sets

-   `GET /v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets`
-   `POST /v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets`
-   `PATCH /v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets/{set_id}`
-   `DELETE /v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets/{set_id}`

---

## Quickstart

1. Copy environment variables:

    - `cp .env.example .env`

2. Start the stack:

    - `docker compose up -d`

3. Run migrations:

    - `docker compose exec api alembic upgrade head`

4. (Optional) Seed an admin user:
    - Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` in `.env`
    - `docker compose exec api python scripts/seed_admin.py`

## Tests

1. Create test environment:

    - `cp .env.example .env.test`

2. Run testing script:

    ```
    ./scripts/test.sh
    ```
