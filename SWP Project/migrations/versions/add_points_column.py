"""add points column to users table

Revision ID: add_points_column
Revises: f2b389a9dba8_add_is_admin_column_to_user_table
Create Date: 2023-08-10 15:37:10.662979

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_points_column'
down_revision = 'f2b389a9dba8_add_is_admin_column_to_user_table'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('points', sa.Integer(), nullable=False, server_default='0'))


def downgrade():
    op.drop_column('users', 'points')
