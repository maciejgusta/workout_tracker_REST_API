from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.schemas.workouts import WorkoutCreate, WorkoutResponse, WorkoutUpdate
from app.models.workout import Workout
from app.models.user import User, UserRole
from sqlalchemy.exc import SQLAlchemyError


def workout_to_response(workout: Workout, is_admin: bool) -> WorkoutResponse:
    response = WorkoutResponse.model_validate(workout)
    if is_admin:
        return response
    return response.model_copy(
        update={"user_id": None, "created_at": None, "updated_at": None}
    )


def create_one(db: Session, workout_in: WorkoutCreate, user_id: int) -> Workout:
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        workout = Workout(
            name=workout_in.name,
            user_id=user_id,
        )
        db.add(workout)
        db.commit()
        db.refresh(workout)
        return workout
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create workout",
        ) from exc


def get_list(db: Session, user: User) -> list[Workout]:
    try:
        stmt = select(Workout).order_by(Workout.created_at)
        if not user.role == UserRole.ADMIN:
            stmt = stmt.where(Workout.user_id == user.id)
        return db.execute(stmt).scalars().all()
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list workouts",
        ) from exc


def get_one(db: Session, workout_id: int, user: User) -> Workout:
    try:
        stmt = select(Workout).where(Workout.id == workout_id)
        if user.role != UserRole.ADMIN:
            stmt = stmt.where(Workout.user_id == user.id)
        workout = db.execute(stmt).scalar_one_or_none()
        if workout is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Workout not found"
            )
        return workout
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get workout",
        ) from exc


def update_one(
    db: Session, workout_id: int, payload: WorkoutUpdate, user: User
) -> Workout:
    values = payload.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No fields provided"
        )
    try:
        workout = get_one(db, workout_id, user)
        for key, value in values.items():
            setattr(workout, key, value)
        db.commit()
        db.refresh(workout)
        return workout
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update workout",
        ) from exc


def delete_one(db: Session, workout_id: int, user: User) -> None:
    try:
        workout = get_one(db, workout_id, user)
        db.delete(workout)
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete workout",
        ) from exc
