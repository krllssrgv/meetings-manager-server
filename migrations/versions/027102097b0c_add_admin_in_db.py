"""Add admin in db

Revision ID: 027102097b0c
Revises: 
Create Date: 2024-07-26 12:25:55.025453

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '027102097b0c'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('admin', sa.Boolean(), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('admin')

    # ### end Alembic commands ###
