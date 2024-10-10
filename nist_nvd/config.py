from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    api_key: Optional[str] = Field(None)

    model_config = SettingsConfigDict(env_prefix="NVD_")
