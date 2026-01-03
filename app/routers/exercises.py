from fastapi import APIRouter, status, Depends
from app.models.user import User, UserRole
from app.dependencies import get_current_user, get_db, require_admin
from sqlalchemy.orm import Session
from app.schemas.exercises import (
    ExerciseResponse,
    ExerciseCreate,
    ExerciseUpdate,
    ExercisesFilterParams,
    ExercisesListResponse,
)
from app.schemas.pagination import PaginationParams
from app.services import exercises

router = APIRouter(prefix="/exercises", tags=["exercises"])


@router.get(
    "/",
    status_code=status.HTTP_200_OK,
    response_model=ExercisesListResponse,
    response_model_exclude_none=True,
    summary="List exercises",
    description="Returns list of exercises; use query params for filtering or pagination",
    responses={
        200: {"description": "Exercises returned"},
        401: {"description": "Could not validate credentials"},
    },
)
def exercises_get_list(
    pagination: PaginationParams = Depends(),
    filters: ExercisesFilterParams = Depends(),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ExercisesListResponse:
    is_admin = current_user.role == UserRole.ADMIN
    items, total = exercises.list_exercises(db, pagination, filters, is_admin)
    return ExercisesListResponse(
        items=exercises.exercises_to_response(items, is_admin),
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=ExerciseResponse,
    response_model_exclude_none=True,
    summary="Create new exercise",
    description="Creates new exercise and returns object",
    responses={
        201: {"description": "Exercise created"},
        403: {"description": "Admin only"},
        409: {"description": "Exercise name already exists"},
        422: {"description": "Validation error"},
    },
)
def exercises_create_one(
    exercise: ExerciseCreate,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> ExerciseResponse:
    return exercises.create_exercise(db, exercise)


@router.get(
    "/{exercise_id}",
    status_code=status.HTTP_200_OK,
    response_model=ExerciseResponse,
    response_model_exclude_none=True,
    summary="Get exercise",
    description="Returns exercise by id",
    responses={
        200: {"description": "Exercise returned"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Exercise not found"},
        422: {"description": "Validation error"},
    },
)
def exercises_get_one(
    exercise_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ExerciseResponse:
    is_admin = current_user.role == UserRole.ADMIN
    exercise = exercises.get_exercise_by_id(db, exercise_id, is_admin)
    return exercises.exercise_to_response(exercise, is_admin)


@router.patch(
    "/{exercise_id}",
    status_code=status.HTTP_200_OK,
    response_model=ExerciseResponse,
    summary="Update exercise",
    description="Updates exercise by id, returns the updated object",
    responses={
        200: {"description": "Exercise updated"},
        400: {"description": "No fields provided"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin only"},
        404: {"description": "Exercise not found"},
        409: {"description": "Exercise name already exists"},
        422: {"description": "Validation error"},
    },
)
def exercises_update_one(
    exercise_id: int,
    exercise_payload: ExerciseUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> ExerciseResponse:
    return exercises.update_exercise(db, exercise_id, exercise_payload)


@router.delete(
    "/{exercise_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete exercise",
    description="Soft deletes exercise by id",
    responses={
        204: {"description": "Exercise deleted"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin only"},
        404: {"description": "Exercise not found"},
    },
)
def exercise_delete_one(
    exercise_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    exercises.delete_exercise(db, exercise_id)
