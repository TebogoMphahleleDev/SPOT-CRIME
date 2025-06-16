"""Add is_admin column to community_chat_messages table

Revision ID: add_is_admin_column_to_community_chat_message
Revises: add_community_chat_message_table
Create Date: 2024-06-01 00:10:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_is_admin_column_to_community_chat_message'
down_revision = 'add_community_chat_message_table'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('community_chat_messages', sa.Column('is_admin', sa.Boolean, nullable=False, server_default=sa.false()))

def downgrade():
    op.drop_column('community_chat_messages', 'is_admin')
