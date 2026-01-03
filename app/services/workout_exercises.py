from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.models.user import User, UserRole
from app.models.workout_exercise import WorkoutExercise
from app.schemas.workout_exercises import (
    WorkoutExercisesResponse,
    WorkoutExerciseCreate,
    WorkoutExerciseUpdate,
)
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import select, func, update
from app.services import workouts, exercises


def workout_exercise_to_response(
    workout_exercise: WorkoutExercise,
    is_admin: bool,
) -> WorkoutExercisesResponse:
    response = WorkoutExercisesResponse.model_validate(
        workout_exercise,
        from_attributes=True,
    )
    if is_admin:
        return response
    return response.model_copy(update={"created_at": None, "updated_at": None})


def get_count(db: Session, workout_id: int) -> int:
    """
    ensure workout_id is valid
    """
    try:
        stmt = (
            select(func.count())
            .select_from(WorkoutExercise)
            .where(WorkoutExercise.workout_id == workout_id)
        )
        return db.execute(stmt).scalar_one()
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get workout exercises count",
        ) from exc


def adjust_positions(
    db: Session, workout_id: int, ge: int, le: int, offset: int
) -> None:
    """
    ensure workout_id is validated for the current user
    rollback done on a higher level for atomicity
    """
    if ge > le:
        return
    try:
        stmt = (
            update(WorkoutExercise)
            .where(WorkoutExercise.workout_id == workout_id)
            .where(WorkoutExercise.position >= ge, WorkoutExercise.position <= le)
            .values(position=WorkoutExercise.position + offset)
        )
        db.execute(stmt)
    except SQLAlchemyError as exc:
        raise SQLAlchemyError(
            "Failed to adjust positions of other exercises in the workout"
        ) from exc


def get_list(db: Session, workout_id: int, user: User) -> list[WorkoutExercise]:
    try:
        workout = workouts.get_one(db, workout_id, user)
        stmt = (
            select(WorkoutExercise)
            .where(WorkoutExercise.workout_id == workout.id)
            .order_by(WorkoutExercise.position)
        )
        return db.execute(stmt).scalars().all()
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list workout exercises",
        ) from exc


def get_one(
    db: Session, workout_id: int, workout_exercise_id: int, user: User
) -> WorkoutExercise:
    try:
        workout = workouts.get_one(db, workout_id, user)
        stmt = select(WorkoutExercise).where(
            WorkoutExercise.workout_id == workout.id,
            WorkoutExercise.id == workout_exercise_id,
        )
        workout_exercise = db.execute(stmt).scalar_one_or_none()
        if workout_exercise is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workout exercise not found",
            )
        return workout_exercise
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get workout exercise",
        ) from exc


def create_one(
    db: Session, workout_id: int, workout_exercise_in: WorkoutExerciseCreate, user: User
) -> WorkoutExercise:
    try:
        is_admin = user.role == UserRole.ADMIN
        workout = workouts.get_one(db, workout_id, user)
        exercise = exercises.get_exercise_by_id(
            db, workout_exercise_in.exercise_id, is_admin
        )
        total = get_count(db, workout_id)

        position = workout_exercise_in.position
        if position is None:
            position = total + 1
        position = min(total + 1, position)
        adjust_positions(db, workout.id, position, total, 1)

        workout_exercise = WorkoutExercise(
            workout_id=workout.id,
            exercise_id=exercise.id,
            position=position,
        )
        db.add(workout_exercise)
        db.commit()
        db.refresh(workout_exercise)
        return workout_exercise
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create workout exercise",
        ) from exc


def update_one(
    db: Session,
    workout_id: int,
    workout_exercise_id: int,
    payload: WorkoutExerciseUpdate,
    user: User,
) -> WorkoutExercise:
    is_admin = user.role == UserRole.ADMIN
    values = payload.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No fields provided"
        )
    workout_exercise = get_one(
        db, workout_id, workout_exercise_id, user
    )  # assert both workout and workout exercises exist
    total = get_count(db, workout_id)
    pos = values.get("position")
    if pos is not None:
        values.update({"position": min(pos, total + 1)})
    try:
        # ensure exercise with the new id exists if set
        if payload.exercise_id and not exercises.check_exercise_exists(
            db, payload.exercise_id, is_admin
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Exercise with the given id does not exist",
            )
        pos = values.get("position")
        if pos is not None:  # adjust positions for the change
            if pos < workout_exercise.position:
                adjust_positions(db, workout_id, pos, workout_exercise.position - 1, 1)
            elif pos > workout_exercise.position:
                adjust_positions(db, workout_id, workout_exercise.position + 1, pos, -1)
        for key, value in values.items():
            setattr(workout_exercise, key, value)
        db.commit()
        db.refresh(workout_exercise)
        return workout_exercise
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Failed to update exercise: position conflict",
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update workout exercise",
        ) from exc


def delete_one(
    db: Session, workout_id: int, workout_exercise_id: int, user: User
) -> None:
    workout_exercise = get_one(db, workout_id, workout_exercise_id, user)
    total = get_count(db, workout_id)
    try:
        db.delete(workout_exercise)
        adjust_positions(db, workout_id, workout_exercise.position + 1, total, -1)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Failed to delete workout exercise: position conflict",
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete workout exercise",
        ) from exc
