from pydantic import BaseModel, Field


class Report(BaseModel):
    title: str = Field(..., min_length=1, max_length=2000)
    location: str = Field(default="", max_length=200)
    url: str = Field(default="", max_length=2048)
    status: str = Field(default="new", max_length=64)
    analyst_notes: str = Field(default="", max_length=8000)


class UrlReport(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    context: str = Field(default="", max_length=8000)


class ReportUpdate(BaseModel):
    status: str = Field(..., min_length=1, max_length=64)
    analyst_notes: str = Field(default="", max_length=8000)
