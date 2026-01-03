import os
import sys
from sqlalchemy import func
from app.core.security import hash_password
from app.db.database import SessionLocal
from app.models.user import User, UserRole
from app.models.exercise import Exercise, ExerciseMuscle, ExerciseEquipment
from app.models.workout import Workout
from app.models.workout_exercise import WorkoutExercise
from app.models.set import Set as SetModel


def get_or_create_user(db, username: str, password: str, role: UserRole) -> User:
    user = db.query(User).filter(User.username == username).first()
    if user:
        return user
    user = User(
        username=username,
        password_hash=hash_password(password),
        role=role,
    )
    db.add(user)
    db.flush()
    return user


def get_or_create_exercise(
    db,
    name: str,
    primary_muscle: ExerciseMuscle,
    equipment: ExerciseEquipment,
    is_active: bool = True,
) -> Exercise:
    exercise = db.query(Exercise).filter(Exercise.name == name).first()
    if exercise:
        return exercise
    exercise = Exercise(
        name=name,
        primary_muscle=primary_muscle,
        equipment=equipment,
        is_active=is_active,
    )
    db.add(exercise)
    db.flush()
    return exercise


def get_or_create_workout(db, user_id: int, name: str) -> Workout:
    workout = (
        db.query(Workout)
        .filter(Workout.user_id == user_id, Workout.name == name)
        .first()
    )
    if workout:
        return workout
    workout = Workout(user_id=user_id, name=name)
    db.add(workout)
    db.flush()
    return workout


def get_or_create_workout_exercise(
    db, workout_id: int, exercise_id: int, position: int | None = None
) -> WorkoutExercise:
    existing = (
        db.query(WorkoutExercise)
        .filter(
            WorkoutExercise.workout_id == workout_id,
            WorkoutExercise.exercise_id == exercise_id,
        )
        .first()
    )
    if existing:
        return existing
    if position is None:
        max_pos = (
            db.query(func.max(WorkoutExercise.position))
            .filter(WorkoutExercise.workout_id == workout_id)
            .scalar()
        )
        position = 1 if max_pos is None else int(max_pos) + 1
    workout_exercise = WorkoutExercise(
        workout_id=workout_id, exercise_id=exercise_id, position=position
    )
    db.add(workout_exercise)
    db.flush()
    return workout_exercise


def get_or_create_set(
    db,
    workout_exercise_id: int,
    set_index: int,
    repetitions: int,
    weight: float | None = None,
    rpe: int | None = None,
) -> SetModel:
    existing = (
        db.query(SetModel)
        .filter(
            SetModel.workout_exercise_id == workout_exercise_id,
            SetModel.set_index == set_index,
        )
        .first()
    )
    if existing:
        return existing
    workout_set = SetModel(
        workout_exercise_id=workout_exercise_id,
        set_index=set_index,
        repetitions=repetitions,
        weight=weight,
        rpe=rpe,
    )
    db.add(workout_set)
    db.flush()
    return workout_set


def seed_demo_data():
    admin_username = os.getenv("DEMO_ADMIN_USERNAME", "admin")
    admin_password = os.getenv("DEMO_ADMIN_PASSWORD", "admin1234")
    user_username = os.getenv("DEMO_USER_USERNAME", "demo")
    user_password = os.getenv("DEMO_USER_PASSWORD", "demo1234")
    if not admin_password or not user_password:
        print("Missing demo user password(s).", file=sys.stderr)
        raise SystemExit(1)
    if admin_username == "admin" and admin_password == "admin1234":
        print("Warning: using default demo admin credentials.", file=sys.stderr)
    if user_username == "demo" and user_password == "demo1234":
        print("Warning: using default demo user credentials.", file=sys.stderr)
    if admin_username == admin_password:
        print("Warning: admin username and password are identical.", file=sys.stderr)
    if user_username == user_password:
        print("Warning: user username and password are identical.", file=sys.stderr)

    db = SessionLocal()
    try:
        admin = get_or_create_user(db, admin_username, admin_password, UserRole.ADMIN)
        user = get_or_create_user(db, user_username, user_password, UserRole.USER)

        exercises = [
            ("Bench Press", ExerciseMuscle.CHEST, ExerciseEquipment.BARBELL, True),
            ("Pull Up", ExerciseMuscle.BACK, ExerciseEquipment.BODYWEIGHT, True),
            ("Squat", ExerciseMuscle.LEGS, ExerciseEquipment.BARBELL, True),
            ("Deadlift", ExerciseMuscle.BACK, ExerciseEquipment.BARBELL, True),
            ("Dumbbell Curl", ExerciseMuscle.BICEPS, ExerciseEquipment.DUMBBELL, True),
            (
                "Cable Triceps Pressdown",
                ExerciseMuscle.TRICEPS,
                ExerciseEquipment.CABLE,
                True,
            ),
            (
                "Hanging Leg Raise",
                ExerciseMuscle.ABS,
                ExerciseEquipment.BODYWEIGHT,
                True,
            ),
            (
                "Behind the Neck Press",
                ExerciseMuscle.TRICEPS,
                ExerciseEquipment.BARBELL,
                False,
            ),
        ]
        exercise_rows = [
            get_or_create_exercise(db, name, muscle, equipment, is_active)
            for name, muscle, equipment, is_active in exercises
        ]

        upper = get_or_create_workout(db, user.id, "Upper Body")
        lower = get_or_create_workout(db, user.id, "Lower Body")

        upper_exercises = {
            "Bench Press": (3, 80.0),
            "Pull Up": (3, None),
            "Dumbbell Curl": (2, 14.0),
        }
        for name, (sets, weight) in upper_exercises.items():
            exercise = next(x for x in exercise_rows if x.name == name)
            we = get_or_create_workout_exercise(db, upper.id, exercise.id)
            for idx in range(1, sets + 1):
                get_or_create_set(
                    db,
                    we.id,
                    idx,
                    repetitions=8 if name != "Pull Up" else 10,
                    weight=weight,
                    rpe=8,
                )

        lower_exercises = {
            "Squat": (3, 100.0),
            "Deadlift": (2, 120.0),
        }
        for name, (sets, weight) in lower_exercises.items():
            exercise = next(x for x in exercise_rows if x.name == name)
            we = get_or_create_workout_exercise(db, lower.id, exercise.id)
            for idx in range(1, sets + 1):
                get_or_create_set(
                    db,
                    we.id,
                    idx,
                    repetitions=5,
                    weight=weight,
                    rpe=8,
                )

        get_or_create_workout(db, admin.id, "Admin Demo Workout")

        db.commit()
        print("Seeded demo data.")
    except Exception as exc:
        db.rollback()
        print(f"Seed failed: {exc}", file=sys.stderr)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_demo_data()
