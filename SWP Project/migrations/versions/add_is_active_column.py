"""add is_active column to user table

Revision ID: 5d84a2b47c3a
Revises: f2b389a9dba8
Create Date: 2023-07-18 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5d84a2b47c3a'
down_revision = 'f2b389a9dba8'
branch_labels = None
depends_on = None


def upgrade():
    # Add is_active column to users table
    op.add_column('users', sa.Column('is_active', sa.Boolean(), nullable=True, server_default='1'))


def downgrade():
    # Remove is_active column from users table
    op.drop_column('users', 'is_active')
