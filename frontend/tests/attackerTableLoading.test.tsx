import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AttackerTable } from '../src/components/dashboard/AttackerTable';
import { mockResult } from '../src/mock/mockResult';

describe('attacker table loading state', () => {
  it('shows a small accessible skeleton while loading', () => {
    render(<AttackerTable loading onRowClick={vi.fn()} rows={mockResult.session.summaries} />);

    expect(screen.getByRole('status', { name: 'Loading attackers' })).toHaveAttribute('aria-busy', 'true');
    expect(screen.queryByText(mockResult.session.summaries[0].ip)).toBeNull();
    expect(screen.getByRole('status', { name: 'Loading attackers' }).querySelectorAll('tbody tr')).toHaveLength(5);
  });
});
