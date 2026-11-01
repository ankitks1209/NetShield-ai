import math
from typing import Literal
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

Role = Literal['analyst', 'administrator']
Dataset = Literal['cicids2017', 'unsw-nb15']

def validate_password(value):
    if len(value) < 12 or len(value.encode('utf-8')) > 72:
        raise ValueError('Password must contain at least 12 characters and at most 72 UTF-8 bytes')
    return value

class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    full_name: str = Field(min_length=1, max_length=120)
    username: str = Field(min_length=3, max_length=60, pattern=r'^[A-Za-z0-9_.-]+$')
    email: EmailStr
    password: str
    role: Literal['analyst'] = 'analyst'
    _password = field_validator('password')(validate_password)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    full_name: str
    username: str
    email: str
    role: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'
    user: UserResponse

class PredictionRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    dataset: Dataset = 'cicids2017'
    features: list[float] | dict[str, float | str] = Field(default_factory=list)
    source_ip: str = Field(default='API input', max_length=100)
    force_attack: bool = False

    @field_validator('features')
    @classmethod
    def finite_values(cls, value):
        values = value.values() if isinstance(value, dict) else value
        if any(isinstance(v, (float, int)) and not math.isfinite(v) for v in values):
            raise ValueError('Feature values must be finite')
        return value

class UpdateAlertRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['Open', 'Investigating', 'False Positive', 'Closed'] | None = None
    assignee: str | None = Field(default=None, max_length=160)
    note: str | None = Field(default=None, min_length=1, max_length=4000)

class ProfileUpdateRequest(BaseModel):
    full_name: str = Field(min_length=1, max_length=120)
    email: EmailStr

class PasswordUpdateRequest(BaseModel):
    current_password: str
    new_password: str
    _password = field_validator('new_password')(validate_password)

class UserUpdateRequest(BaseModel):
    role: Role
    is_active: bool

class InviteRequest(BaseModel):
    email: EmailStr
    role: Role = 'analyst'
