from sqlalchemy.orm import Session
from schemas.profileSchema import ProfileSchema
from models.profile import Profile
from fastapi import HTTPException, status


def get_profile_all(db: Session, limit: int = 100, offset: int = 0):
    try:
        result = (db.query(Profile).offset(offset).limit(limit).all())
        return result
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Error al obtener perfiles {e}")

def get_profile_by_id(db: Session, perfil_id: int):
    try:
        result = db.query(Profile).filter(Profile.id == perfil_id).first()
        return result
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Error al buscar perfil {e}")


def create_profile(db: Session, perfil: ProfileSchema):
    try:
        _profile = Profile(
            name=perfil.name,
            description=perfil.description
        )

        db.add(_profile)
        db.commit()
        db.refresh(_profile)
        return _profile
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,detail=f"Error creando perfil {e}")

def delete_profile(db: Session, profile_id: int):
    try:
        profile_to_delete = db.query(Profile).filter(Profile.id == profile_id).first()
        if profile_to_delete:
            db.delete(profile_to_delete)
            db.commit()
            return profile_id
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Perfil con id {profile_id} no encontrado")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error eliminando perfil: {e}")