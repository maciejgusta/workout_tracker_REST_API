from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select, update, func
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from app.models.exercise import Exercise
from app.schemas.exercises import ExerciseCreate, ExerciseResponse, ExerciseUpdate, ExercisesFilterParams
from app.schemas.pagination import PaginationParams
from typing import List

def exercise_to_response(exercise: Exercise, is_admin: bool) -> ExerciseResponse:
    response = ExerciseResponse.model_validate(exercise)
    if is_admin:
        return response
    return response.model_copy(
        update={"is_active": None, "created_at": None, "updated_at": None}
    )

def exercises_to_response(exercises: List[Exercise], is_admin: bool) -> List[ExerciseResponse]:
    return [exercise_to_response(item, is_admin) for item in exercises]

def list_exercises(
        db: Session,
        pagination: PaginationParams,
        filters: ExercisesFilterParams,
        is_admin: bool = False
) -> tuple[List[Exercise], int]:
    try:
        conditions = []
        if not is_admin:
            conditions.append(Exercise.is_active.is_(True))
        if filters.name:
            conditions.append(Exercise.name.ilike(f"%{filters.name}%"))

        total_stmt = select(func.count()).select_from(Exercise)
        if conditions:
            total_stmt = total_stmt.where(*conditions)
        total = db.execute(total_stmt).scalar_one()

        stmt = select(Exercise).order_by(Exercise.name)
        if conditions:
            stmt = stmt.where(*conditions)
        stmt = stmt.limit(pagination.limit).offset(pagination.offset)
        exercises = db.execute(stmt).scalars().all()
        return exercises, total
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Failed to get exercises"
        ) from exc
    
def get_exercise_by_id(db: Session, id: int, is_admin: bool = False) -> Exercise:
    try:
        stmt = select(Exercise).where(Exercise.id == id)
        if not is_admin:
            stmt = stmt.where(Exercise.is_active.is_(True))
        exercise = db.execute(stmt).scalar_one_or_none()
        if exercise is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Exercise not found"
            )
        return exercise
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get exercise"
        ) from exc
    
def create_exercise(db: Session, exercise_in: ExerciseCreate):
    try:
        exercise = Exercise(**exercise_in.model_dump())
        db.add(exercise)
        db.commit()
        db.refresh(exercise)
        return exercise
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Exercise name already exists"
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create exercise"
        ) from exc
    
def update_exercise(db: Session, exercise_id: int, payload: ExerciseUpdate) -> Exercise:
    try:
        values = payload.model_dump(exclude_unset=True)
        if not values:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="No fields provided"
            )

        stmt = (update(Exercise)
                .where(Exercise.id == exercise_id)
                .values(**values)
                .returning(Exercise))
        
        result = db.execute(stmt)
        exercise = result.scalar_one_or_none()
        if exercise is None:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Exercise not found"
            )
        db.commit()
        return exercise
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Exercise name already exists"
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update exercise"
        ) from exc
        
def delete_exercise(db: Session, exercise_id: int) -> None:
    try:
        stmt = update(Exercise).where(Exercise.id == exercise_id).values(is_active=False).returning(Exercise)
        result = db.execute(stmt)
        exercise = result.scalar_one_or_none()
        if (exercise is None):
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Exercise not found"
            )
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete exercise"
        ) from exc
