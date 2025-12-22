# Workout Tracker API

A production-grade REST API for tracking workouts, exercises, and sets. Built with **FastAPI** and **PostgreSQL**, with **migrations**, **tests**, and a **CI pipeline**.

> Goal: demonstrate real backend engineering practices (clean architecture, validation, auth, testing, documentation, CI).

---

## Features

-   User authentication (JWT access token + refresh token)
-   CRUD for exercises
-   Workout sessions with exercises + sets (reps/weight/RPE)
-   Input validation + consistent error responses
-   PostgreSQL schema with constraints + migrations (Alembic)
-   Automated tests (unit + intergration)
-   CI pipeline (lint + tests + coverage) via GitHub Actions
-   OpenAPI docs (Swagger UI)

---

## Tech Stack

-   **Python**: 3.13.3
-   **API**: FastAPI, Pydantic v2
-   **DB**: PostgreSQL
-   **ORM**: SQLAlchemy 2.0
-   **Migrations**: Alembic
-   **Auth**: JWT (access + refresh), bcrypt password hashing
-   **Tests**: pytest, httpx
-   **Quality**: ruff
-   **CI**: GitHub Actions
-   **Dev**: Docker Compose

---

## Architecture

The projects uses a layered structure to keep HTTP concerns separate from business rules and persistance:

-   `api` - FastAPI initialization and routing
-   `schemas/` - Pydantic models (API contract)
-   `services/` - business logic (permissions, domain rules)
-   `models/` - SQLAlchemy models (DB entities)
-   `db/` - session/engine + migrations
-   `core/` - configuration and security settings

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

-   All user-owned resources are scoperd by `user_id`
-   DB-level constaints prevent invalid values (e.g. reps > 0, weight >= 0)

---

## API Overview

Base path: `/v1`

### Auth

-   `POST /v1/auth/register`
-   `POST /v1/auth/login`
-   `POST /v1/auth/refresh`
-   `POST /v1/auth/logout`
