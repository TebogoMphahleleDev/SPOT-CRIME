"""Add community_chat_messages table

Revision ID: add_community_chat_message_table
Revises: 
Create Date: 2024-06-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_community_chat_message_table'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'community_chat_messages',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('username', sa.String(100), nullable=False),
        sa.Column('message', sa.Text, nullable=False),
        sa.Column('timestamp', sa.DateTime, nullable=False, server_default=sa.func.now())
    )


def downgrade():
    op.drop_table('community_chat_messages')
