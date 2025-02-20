import os
from pathlib import Path
from typing import Optional

from open_webui.models.auths import Auths, SigninResponse, AddUserForm
from open_webui.models.chats import ChatTitleIdResponse, Chats, ChatResponse
from open_webui.models.users import Users, UserUpdateForm, UserModel
from open_webui.models.groups import (
    Groups,
    GroupForm,
    GroupUpdateForm,
    GroupResponse, log,
)

from open_webui.config import CACHE_DIR, ENABLE_ADMIN_CHAT_ACCESS
from open_webui.constants import ERROR_MESSAGES
from fastapi import APIRouter, Depends, HTTPException, Request, status
from open_webui.utils.auth import get_admin_user, get_verified_user, get_password_hash, create_token

from open_webui.models.users import UserResponse
from open_webui.utils.auth import get_group_admin_user
from open_webui.utils.misc import validate_email_format

router = APIRouter()


############################
# GetFunctions
############################


@router.get("/", response_model=list[GroupResponse])
async def get_groups(user=Depends(get_verified_user)):
    if user.role == "admin":
        return Groups.get_groups()
    else:
        return Groups.get_groups_by_member_id(user.id)


@router.get("/users", response_model=list[UserModel])
async def get_group_members(userGroups=Depends(get_group_admin_user)):
    user, groups = userGroups
    if user.role == "admin":
        return Users.get_users()

    user_ids = []
    for group in groups:
        user_ids += Groups.get_group_user_ids_by_id(group.id)
    return Users.get_users_by_user_ids(user_ids)


@router.post("/user/{user_id}/update", response_model=Optional[UserModel])
async def update_user_by_id(
        user_id: str,
        form_data: UserUpdateForm,
        session=Depends(get_group_admin_user),
):
    session_user, session_groups = session

    group_users = Groups.get_group_user_ids_by_id(session_groups[0].id)
    if user_id not in group_users and session_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )
    user = Users.get_user_by_id(user_id)

    if user:
        if form_data.email.lower() != user.email:
            email_user = Users.get_user_by_email(form_data.email.lower())
            if email_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ERROR_MESSAGES.EMAIL_TAKEN,
                )

        if form_data.password:
            hashed = get_password_hash(form_data.password)
            log.debug(f"hashed: {hashed}")
            Auths.update_user_password_by_id(user_id, hashed)

        Auths.update_email_by_id(user_id, form_data.email.lower())
        updated_user = Users.update_user_by_id(
            user_id,
            {
                "name": form_data.name,
                "email": form_data.email.lower(),
                "profile_image_url": form_data.profile_image_url,
            },
        )

        if updated_user:
            return updated_user

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(),
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=ERROR_MESSAGES.USER_NOT_FOUND,
    )


@router.delete("/user/{user_id}", response_model=bool)
async def delete_user_by_id(user_id: str, session=Depends(get_group_admin_user)):
    session_user, session_groups = session

    group_users = Groups.get_group_user_ids_by_id(session_groups[0].id)
    if user_id not in group_users and session_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )

    if session_user.id != user_id:
        result = Auths.delete_auth_by_id(user_id)

        if result:
            return True

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ERROR_MESSAGES.DELETE_USER_ERROR,
        )

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=ERROR_MESSAGES.ACTION_PROHIBITED,
    )


@router.post("/add-user", response_model=SigninResponse)
async def add_user(form_data: AddUserForm, session=Depends(get_group_admin_user)):
    session_user, session_groups = session
    if len(session_groups) <= 0 and session_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )

    if not validate_email_format(form_data.email.lower()):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail=ERROR_MESSAGES.INVALID_EMAIL_FORMAT
        )

    if Users.get_user_by_email(form_data.email.lower()):
        raise HTTPException(400, detail=ERROR_MESSAGES.EMAIL_TAKEN)

    try:
        hashed = get_password_hash(form_data.password)
        user = Auths.insert_new_auth(
            form_data.email.lower(),
            hashed,
            form_data.name,
            form_data.profile_image_url,
            form_data.role,
        )

        if user:
            group = session_groups[0]
            if not Groups.add_user_to_group(group.id, user.id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ERROR_MESSAGES.DEFAULT("Error add group"),
                )

            token = create_token(data={"id": user.id})
            return {
                "token": token,
                "token_type": "Bearer",
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "profile_image_url": user.profile_image_url,
            }
        else:
            raise HTTPException(500, detail=ERROR_MESSAGES.CREATE_USER_ERROR)
    except Exception as err:
        raise HTTPException(500, detail=ERROR_MESSAGES.DEFAULT(err))


@router.get("/list/user/{user_id}", response_model=list[ChatTitleIdResponse])
async def get_user_chat_list_by_user_id(
    user_id: str,
    session=Depends(get_group_admin_user),
    skip: int = 0,
    limit: int = 50,
):
    session_user, session_groups = session
    group_users = Groups.get_group_user_ids_by_id(session_groups[0].id)
    if user_id not in group_users and session_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )

    if not ENABLE_ADMIN_CHAT_ACCESS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return Chats.get_chat_list_by_user_id(
        user_id, include_archived=True, skip=skip, limit=limit
    )

@router.get("/share/{share_id}", response_model=Optional[ChatResponse])
async def get_shared_chat_by_id(share_id: str, session=Depends(get_group_admin_user)):
    session_user, session_groups = session
    group_users = Groups.get_group_user_ids_by_id(session_groups[0].id)
    chat = Chats.get_chat_by_id(share_id)
    if chat and chat.user_id in group_users:
        return ChatResponse(**chat.model_dump())

    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=ERROR_MESSAGES.NOT_FOUND
        )
############################
# CreateNewGroup
############################


@router.post("/create", response_model=Optional[GroupResponse])
async def create_new_function(form_data: GroupForm, user=Depends(get_admin_user)):
    try:
        group = Groups.insert_new_group(user.id, form_data)
        if group:
            return group
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error creating group"),
            )
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )


############################
# GetGroupById
############################


@router.get("/id/{id}", response_model=Optional[GroupResponse])
async def get_group_by_id(id: str, user=Depends(get_admin_user)):
    group = Groups.get_group_by_id(id)
    if group:
        return group
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


############################
# UpdateGroupById
############################


@router.post("/id/{id}/update", response_model=Optional[GroupResponse])
async def update_group_by_id(
        id: str, form_data: GroupUpdateForm, user=Depends(get_admin_user)
):
    try:
        if form_data.user_ids:
            form_data.user_ids = Users.get_valid_user_ids(form_data.user_ids)

        group = Groups.update_group_by_id(id, form_data)
        if group:
            return group
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error updating group"),
            )
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )


############################
# DeleteGroupById
############################


@router.delete("/id/{id}/delete", response_model=bool)
async def delete_group_by_id(id: str, user=Depends(get_admin_user)):
    try:
        result = Groups.delete_group_by_id(id)
        if result:
            return result
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error deleting group"),
            )
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )
