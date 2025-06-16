"""Add reset_token and reset_token_expiry columns to users table

Revision ID: add_reset_token_columns
Revises: 
Create Date: 2024-06-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_reset_token_columns'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('reset_token', sa.String(length=200), nullable=True))
    op.add_column('users', sa.Column('reset_token_expiry', sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column('users', 'reset_token')
    op.drop_column('users', 'reset_token_expiry')
