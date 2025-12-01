"""add used_at to email_verification_tokens

Revision ID: e8f9a1b2c3d4
Revises: 0540f191154c
Create Date: 2025-12-01 21:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e8f9a1b2c3d4'
down_revision: Union[str, Sequence[str], None] = '0540f191154c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - Add used_at column to email_verification_tokens table."""
    # Add used_at column
    op.add_column('email_verification_tokens',
                  sa.Column('used_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema - Remove used_at column from email_verification_tokens table."""
    # Remove used_at column
    op.drop_column('email_verification_tokens', 'used_at')
