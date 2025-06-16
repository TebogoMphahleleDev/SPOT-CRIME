"""Add profile_image column to users table

Revision ID: add_profile_image_column_to_user
Revises: 
Create Date: 2024-06-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_profile_image_column_to_user'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('users', sa.Column('profile_image', sa.String(length=255), nullable=True))

def downgrade():
    op.drop_column('users', 'profile_image')
