"""Add LLM analysis fields

Revision ID: 2271ed08ad8f
Revises: 1271ed08ad8e
Create Date: 2025-02-25 10:15:32.940555

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2271ed08ad8f'
down_revision: Union[str, None] = '1271ed08ad8e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add LLM analysis fields to CodeQL findings
    op.add_column('codeql_findings', sa.Column('llm_verification', sa.Text(), nullable=True))
    op.add_column('codeql_findings', sa.Column('llm_exploitability', sa.Text(), nullable=True))
    op.add_column('codeql_findings', sa.Column('llm_remediation', sa.Text(), nullable=True))
    op.add_column('codeql_findings', sa.Column('llm_priority', sa.Text(), nullable=True))
    
    # Add LLM analysis fields to dependency check findings
    op.add_column('dependency_check_findings', sa.Column('llm_exploitability', sa.Text(), nullable=True))
    op.add_column('dependency_check_findings', sa.Column('llm_remediation', sa.Text(), nullable=True))
    op.add_column('dependency_check_findings', sa.Column('llm_priority', sa.Text(), nullable=True))


def downgrade() -> None:
    # Remove LLM analysis fields from CodeQL findings
    op.drop_column('codeql_findings', 'llm_verification')
    op.drop_column('codeql_findings', 'llm_exploitability')
    op.drop_column('codeql_findings', 'llm_remediation')
    op.drop_column('codeql_findings', 'llm_priority')
    
    # Remove LLM analysis fields from dependency check findings
    op.drop_column('dependency_check_findings', 'llm_exploitability')
    op.drop_column('dependency_check_findings', 'llm_remediation')
    op.drop_column('dependency_check_findings', 'llm_priority') 