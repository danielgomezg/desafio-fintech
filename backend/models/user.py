from sqlalchemy import Column, Integer, String, ForeignKey
from database import Base
from sqlalchemy.ext.hybrid import hybrid_property
from passlib.hash import bcrypt
from sqlalchemy.orm import relationship
from models.profile import Profile


class Usuario(Base):
    __tablename__ = 'usuario'
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, unique=True, nullable=False)
    _password = Column(String, nullable=False)
    rut = Column(String, unique=True, nullable=False)

    # Relacion con perfil
    profile_id = Column(Integer, ForeignKey('perfil.id'))

    profile = relationship('Profile', back_populates='users')


    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, plainTextPassword):
        self._password = bcrypt.hash(plainTextPassword)

    @classmethod
    def verify_password(self, password, passwordHash):
        print(password)
        return bcrypt.verify(password, passwordHash)

    def __repr__(self):
        return f"Usuario(nombre={self.email}, correo={self.rut})"