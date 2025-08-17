"""
Migration script to add account lockout fields to the users table
"""
from sqlalchemy import Column, Integer, DateTime
from alembic import op
import sqlalchemy as sa

def upgrade():
    # Add failed_login_attempts column with default value 0
    op.add_column('users', sa.Column('failed_login_attempts', sa.Integer(), nullable=True))
    op.execute('UPDATE users SET failed_login_attempts = 0 WHERE failed_login_attempts IS NULL')
    op.alter_column('users', 'failed_login_attempts', nullable=False, server_default='0')
    
    # Add account_locked_until column
    op.add_column('users', sa.Column('account_locked_until', sa.DateTime(), nullable=True))

def downgrade():
    # Remove the columns if needed
    op.drop_column('users', 'failed_login_attempts')
    op.drop_column('users', 'account_locked_until')
