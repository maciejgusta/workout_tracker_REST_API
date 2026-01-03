from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select, func, update
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from app.models.set import Set
from app.models.user import User
from app.schemas.sets import SetResponse, SetCreate, SetUpdate
from app.services import workout_exercises


def set_to_response(item: Set, is_admin: bool) -> SetResponse:
    response = SetResponse.model_validate(item)
    if is_admin:
        return response
    return response.model_copy(update={"created_at": None, "updated_at": None})


def get_list(
    db: Session,
    workout_id: int,
    workout_exercise_id: int,
    user: User,
) -> list[Set]:
    workout_exercise = workout_exercises.get_one(
        db,
        workout_id,
        workout_exercise_id,
        user,
    )
    try:
        stmt = (
            select(Set)
            .where(Set.workout_exercise_id == workout_exercise.id)
            .order_by(Set.set_index)
        )
        return db.execute(stmt).scalars().all()
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list sets",
        ) from exc


def get_one(
    db: Session,
    workout_id: int,
    workout_exercise_id: int,
    set_id: int,
    user: User,
) -> Set:
    workout_exercise = workout_exercises.get_one(
        db,
        workout_id,
        workout_exercise_id,
        user,
    )
    try:
        stmt = select(Set).where(
            Set.id == set_id,
            Set.workout_exercise_id == workout_exercise.id,
        )
        item = db.execute(stmt).scalar_one_or_none()
        if item is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Set not found",
            )
        return item
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get set",
        ) from exc


def get_count(db: Session, workout_exercise_id: int) -> int:
    try:
        stmt = (
            select(func.count())
            .select_from(Set)
            .where(Set.workout_exercise_id == workout_exercise_id)
        )
        return db.execute(stmt).scalar_one()
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get sets count",
        ) from exc


def adjust_set_indexes(
    db: Session,
    workout_exercise_id: int,
    ge: int,
    le: int,
    offset: int,
) -> None:
    if ge > le:
        return
    try:
        stmt = (
            update(Set)
            .where(Set.workout_exercise_id == workout_exercise_id)
            .where(Set.set_index >= ge, Set.set_index <= le)
            .values(set_index=Set.set_index + offset)
        )
        db.execute(stmt)
    except SQLAlchemyError as exc:
        raise SQLAlchemyError("Failed to adjust set indexes") from exc


def create_one(
    db: Session,
    workout_id: int,
    workout_exercise_id: int,
    set_in: SetCreate,
    user: User,
) -> Set:
    workout_exercise = workout_exercises.get_one(
        db,
        workout_id,
        workout_exercise_id,
        user,
    )
    try:
        total = get_count(db, workout_exercise.id)
        set_index = set_in.set_index
        if set_index is None:
            set_index = total + 1
        set_index = min(total + 1, set_index)
        adjust_set_indexes(db, workout_exercise.id, set_index, total, 1)

        item = Set(
            workout_exercise_id=workout_exercise.id,
            set_index=set_index,
            weight=set_in.weight,
            repetitions=set_in.repetitions,
            rpe=set_in.rpe,
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return item
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Set index conflict",
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create set",
        ) from exc


def update_one(
    db: Session,
    workout_id: int,
    workout_exercise_id: int,
    set_id: int,
    payload: SetUpdate,
    user: User,
) -> Set:
    values = payload.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields provided",
        )
    item = get_one(db, workout_id, workout_exercise_id, set_id, user)
    total = get_count(db, item.workout_exercise_id)
    new_index = values.get("set_index")
    if new_index is not None:
        values.update({"set_index": min(new_index, total)})
    try:
        new_index = values.get("set_index")
        if new_index is not None:
            if new_index < item.set_index:
                adjust_set_indexes(
                    db, item.workout_exercise_id, new_index, item.set_index - 1, 1
                )
            elif new_index > item.set_index:
                adjust_set_indexes(
                    db, item.workout_exercise_id, item.set_index + 1, new_index, -1
                )
        for key, value in values.items():
            setattr(item, key, value)
        db.commit()
        db.refresh(item)
        return item
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Set index conflict",
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update set",
        ) from exc


def delete_one(
    db: Session,
    workout_id: int,
    workout_exercise_id: int,
    set_id: int,
    user: User,
) -> None:
    item = get_one(db, workout_id, workout_exercise_id, set_id, user)
    total = get_count(db, item.workout_exercise_id)
    try:
        db.delete(item)
        adjust_set_indexes(
            db,
            item.workout_exercise_id,
            item.set_index + 1,
            total,
            -1,
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Set index conflict",
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete set",
        ) from exc
