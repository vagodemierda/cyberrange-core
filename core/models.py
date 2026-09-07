from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Text,
    ForeignKey,
    UniqueConstraint,
)

from sqlalchemy.orm import relationship

from core.db import Base


class SessionRun(Base):
    __tablename__ = "session_runs"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    scenario_id = Column(
        String,
        nullable=False
    )

    started_ts = Column(
        Float,
        nullable=False
    )

    finished_ts = Column(
        Float,
        nullable=True
    )

    status = Column(
        String,
        nullable=False,
        default="RUNNING"
    )

    # Roles almacenados como JSON string.
    roles_json = Column(
        Text,
        nullable=False,
        default="{}"
    )

    decisions = relationship(
        "Decision",
        back_populates="session_run"
    )

    inject_releases = relationship(
        "InjectRelease",
        back_populates="session_run",
        cascade="all, delete-orphan"
    )


class Decision(Base):
    __tablename__ = "decisions"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    session_id = Column(
        Integer,
        ForeignKey("session_runs.id"),
        nullable=False
    )

    gate_id = Column(
        String,
        nullable=False
    )

    role = Column(
        String,
        nullable=False
    )

    option_key = Column(
        String,
        nullable=False
    )

    option_score = Column(
        Integer,
        nullable=False
    )

    decided_ts = Column(
        Float,
        nullable=False
    )

    justification = Column(
        Text,
        nullable=True
    )

    session_run = relationship(
        "SessionRun",
        back_populates="decisions"
    )


class InjectRelease(Base):
    __tablename__ = "inject_releases"

    __table_args__ = (
        UniqueConstraint(
            "session_id",
            "inject_id",
            name="uq_session_inject_release"
        ),
    )

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    session_id = Column(
        Integer,
        ForeignKey("session_runs.id"),
        nullable=False,
        index=True
    )

    inject_id = Column(
        String,
        nullable=False
    )

    released_ts = Column(
        Float,
        nullable=False
    )

    telemetry_json = Column(
        Text,
        nullable=True
    )

    session_run = relationship(
        "SessionRun",
        back_populates="inject_releases"
    )
