from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime


class BlocklistBase(BaseModel):
    value: str = Field(..., description="The email or domain to block")
    type: str = Field(..., description="'email' or 'domain'")


class BlocklistCreate(BlocklistBase):
    pass


class BlocklistResponse(BlocklistBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
