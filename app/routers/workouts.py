from fastapi import APIRouter, status, Depends, HTTPException
from app.schemas.workouts import WorkoutResponse, WorkoutCreate, WorkoutUpdate
from app.schemas.workout_exercises import (
    WorkoutExercisesResponse,
    WorkoutExerciseCreate,
    WorkoutExerciseUpdate,
)
from app.schemas.sets import SetResponse, SetCreate, SetUpdate
from app.dependencies import get_current_user, get_db
from sqlalchemy.orm import Session
from app.models.user import User, UserRole
from app.services import workouts, workout_exercises, sets

router = APIRouter(prefix="/workouts", tags=["workouts"])


@router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=WorkoutResponse,
    response_model_exclude_none=True,
    summary="Create workout",
    description="Creates workout for the current user",
    responses={
        201: {"description": "Workout created"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin only"},
        404: {"description": "User not found"},
    },
)
def workouts_create_one(
    workout: WorkoutCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkoutResponse:
    is_admin = current_user.role == UserRole.ADMIN
    if workout.user_id is not None and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setting user id is for admin only",
        )
    user_id = workout.user_id if workout.user_id is not None else current_user.id
    workout_obj = workouts.create_one(db, workout, user_id)
    return workouts.workout_to_response(workout_obj, is_admin)


@router.get(
    "/",
    status_code=status.HTTP_200_OK,
    response_model=list[WorkoutResponse],
    response_model_exclude_none=True,
    summary="List workouts",
    description="Returns list of workouts",
    responses={
        200: {"description": "Workouts returned"},
        401: {"description": "Could not validate credentials"},
    },
)
def workouts_get_list(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[WorkoutResponse]:
    is_admin = current_user.role == UserRole.ADMIN
    items = workouts.get_list(db, current_user)
    return [workouts.workout_to_response(workout, is_admin) for workout in items]


@router.get(
    "/{workout_id}",
    status_code=status.HTTP_200_OK,
    response_model=WorkoutResponse,
    response_model_exclude_none=True,
    summary="Get workout",
    description="Returns workout by id",
    responses={
        200: {"description": "Workout returned"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Workout not found"},
        422: {"description": "Validation error"},
    },
)
def workouts_get_one(
    workout_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkoutResponse:
    is_admin = current_user.role == UserRole.ADMIN
    workout = workouts.get_one(db, workout_id, current_user)
    return workouts.workout_to_response(workout, is_admin)


@router.patch(
    "/{workout_id}",
    status_code=status.HTTP_200_OK,
    response_model=WorkoutResponse,
    response_model_exclude_none=True,
    summary="Update workout",
    description="Updates workout by id",
    responses={
        200: {"description": "Workout updated"},
        400: {"description": "No fields provided"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Workout not found"},
        422: {"description": "Validation error"},
    },
)
def workouts_update_one(
    workout_id: int,
    payload: WorkoutUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> WorkoutResponse:
    is_admin = current_user.role == UserRole.ADMIN
    workout = workouts.update_one(db, workout_id, payload, current_user)
    return workouts.workout_to_response(workout, is_admin)


@router.delete(
    "/{workout_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete workout",
    description="Deletes workout by id",
    responses={
        204: {"description": "Workout deleted"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Workout not found"},
    },
)
def workouts_delete_one(
    workout_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    workouts.delete_one(db, workout_id, current_user)


# Workout exercises routes


@router.get(
    "/{workout_id}/exercises",
    status_code=status.HTTP_200_OK,
    response_model=list[WorkoutExercisesResponse],
    response_model_exclude_none=True,
    tags=["workout_exercises"],
    summary="List workout exercises",
    description="Returns workout exercises by id",
    responses={
        200: {"description": "Workout exercises returned"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Workout not found"},
        422: {"description": "Validation error"},
    },
)
def workout_exercises_get_list(
    workout_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[WorkoutExercisesResponse]:
    is_admin = current_user.role == UserRole.ADMIN
    items = workout_exercises.get_list(db, workout_id, current_user)
    return [
        workout_exercises.workout_exercise_to_response(workout_exercise, is_admin)
        for workout_exercise in items
    ]


@router.post(
    "/{workout_id}/exercises",
    status_code=status.HTTP_201_CREATED,
    response_model=WorkoutExercisesResponse,
    response_model_exclude_none=True,
    tags=["workout_exercises"],
    summary="Create workout exercise",
    description="Creates workout exercise inside of an existing workout",
    responses={
        201: {"description": "Workout exercise created"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Workout not found or exercise not found"},
        409: {"description": "Position not unique"},
        422: {"description": "Validation error"},
    },
)
def workout_exercises_create_one(
    workout_id: int,
    workout_exercise: WorkoutExerciseCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> WorkoutExercisesResponse:
    is_admin = current_user.role == UserRole.ADMIN
    item = workout_exercises.create_one(db, workout_id, workout_exercise, current_user)
    return workout_exercises.workout_exercise_to_response(item, is_admin)


@router.patch(
    "/{workout_id}/exercises/{workout_exercise_id}",
    status_code=status.HTTP_200_OK,
    response_model=WorkoutExercisesResponse,
    response_model_exclude_none=True,
    tags=["workout_exercises"],
    summary="Update workout exercise",
    description="Updates workout exercise by id",
    responses={
        200: {"description": "Workout exercise updated"},
        400: {
            "description": "No fields provided or exercise with the given id does not exist"
        },
        401: {"description": "Could not validate credentials"},
        404: {"description": "Workout or workout exercise not found"},
        409: {"description": "Position conflict"},
        422: {"description": "Validation error"},
    },
)
def workout_exercises_update_one(
    workout_id: int,
    workout_exercise_id: int,
    payload: WorkoutExerciseUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> WorkoutExercisesResponse:
    item = workout_exercises.update_one(
        db, workout_id, workout_exercise_id, payload, current_user
    )
    return workout_exercises.workout_exercise_to_response(
        item, current_user.role == UserRole.ADMIN
    )


@router.delete(
    "/{workout_id}/exercises/{workout_exercise_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["workout_exercises"],
    summary="Delete workout exercise",
    description="Deletes workout exercise by id",
    responses={
        204: {"description": "Workout exercise deleted"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Workout or workout_exercise not found"},
    },
)
def workout_exercises_delete_one(
    workout_id: int,
    workout_exercise_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    workout_exercises.delete_one(db, workout_id, workout_exercise_id, current_user)


# Sets routes


@router.get(
    "/{workout_id}/exercises/{workout_exercise_id}/sets",
    status_code=status.HTTP_200_OK,
    response_model=list[SetResponse],
    response_model_exclude_none=True,
    tags=["sets"],
    summary="List sets",
    description="Returns sets for a workout exercise",
    responses={
        200: {"description": "Sets returned"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Workout or workout exercise not found"},
        422: {"description": "Validation error"},
    },
)
def sets_get_list(
    workout_id: int,
    workout_exercise_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[SetResponse]:
    is_admin = current_user.role == UserRole.ADMIN
    items = sets.get_list(db, workout_id, workout_exercise_id, current_user)
    return [sets.set_to_response(item, is_admin) for item in items]


@router.post(
    "/{workout_id}/exercises/{workout_exercise_id}/sets",
    status_code=status.HTTP_201_CREATED,
    response_model=SetResponse,
    response_model_exclude_none=True,
    tags=["sets"],
    summary="Create set",
    description="Creates set for a workout exercise",
    responses={
        201: {"description": "Set created"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Workout or workout exercise not found"},
        409: {"description": "Set index conflict"},
        422: {"description": "Validation error"},
    },
)
def sets_create_one(
    workout_id: int,
    workout_exercise_id: int,
    payload: SetCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SetResponse:
    is_admin = current_user.role == UserRole.ADMIN
    item = sets.create_one(
        db,
        workout_id,
        workout_exercise_id,
        payload,
        current_user,
    )
    return sets.set_to_response(item, is_admin)


@router.patch(
    "/{workout_id}/exercises/{workout_exercise_id}/sets/{set_id}",
    status_code=status.HTTP_200_OK,
    response_model=SetResponse,
    response_model_exclude_none=True,
    tags=["sets"],
    summary="Update set",
    description="Updates a set by id",
    responses={
        200: {"description": "Set updated"},
        400: {"description": "No fields provided"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Workout, workout exercise, or set not found"},
        409: {"description": "Set index conflict"},
        422: {"description": "Validation error"},
    },
)
def sets_update_one(
    workout_id: int,
    workout_exercise_id: int,
    set_id: int,
    payload: SetUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SetResponse:
    is_admin = current_user.role == UserRole.ADMIN
    item = sets.update_one(
        db,
        workout_id,
        workout_exercise_id,
        set_id,
        payload,
        current_user,
    )
    return sets.set_to_response(item, is_admin)


@router.delete(
    "/{workout_id}/exercises/{workout_exercise_id}/sets/{set_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["sets"],
    summary="Delete set",
    description="Deletes a set by id",
    responses={
        204: {"description": "Set deleted"},
        401: {"description": "Could not validate credentials"},
        404: {"description": "Workout, workout exercise, or set not found"},
    },
)
def sets_delete_one(
    workout_id: int,
    workout_exercise_id: int,
    set_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    sets.delete_one(
        db,
        workout_id,
        workout_exercise_id,
        set_id,
        current_user,
    )
