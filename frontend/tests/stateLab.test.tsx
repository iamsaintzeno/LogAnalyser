import { beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { Dashboard } from '../src/pages/Dashboard';
import { UploadPage } from '../src/pages/UploadPage';
import { IpDetailModal } from '../src/components/dashboard/IpDetailModal';
import { stateLabFixtures } from '../src/mock/stateLabFixtures';
import { useAnalyzerStore } from '../src/store/useAnalyzerStore';

beforeEach(() => {
  cleanup();
  useAnalyzerStore.setState({
    status: 'idle',
    result: null,
    error: null,
    blocklistSelection: {},
    filters: { types: [], from: null, to: null, minScore: 0, ipQuery: '' },
  });
  window.matchMedia = vi.fn().mockImplementation(() => ({
    matches: true,
    media: '',
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
  if (!('showModal' in HTMLDialogElement.prototype)) {
    HTMLDialogElement.prototype.showModal = function showModal() { this.open = true; };
  }
  if (!('close' in HTMLDialogElement.prototype)) {
    HTMLDialogElement.prototype.close = function close() { this.open = false; };
  }
});

describe('State Lab hardening fixtures', () => {
  it('shows a clean-log state with empty activity and a disabled blocklist', () => {
    useAnalyzerStore.getState().setResult(stateLabFixtures.clean);
    render(<Dashboard />);

    expect(screen.getByText('No attacks detected')).toBeTruthy();
    expect(screen.getByText('No attackers match these filters')).toBeTruthy();
    expect(screen.getByText('No attack activity in this log')).toBeTruthy();
    expect(screen.getByText('Blocklist is disabled because no threats were detected.')).toBeTruthy();
    const sliders = screen.getAllByRole('slider');
    expect(sliders.some((slider) => (slider as HTMLInputElement).disabled)).toBe(true);
  });

  it('renders XSS-like path, user-agent, and referer values as text', () => {
    const fixture = stateLabFixtures.xssFixture;
    useAnalyzerStore.getState().setResult(fixture);
    const ip = fixture.session.summaries[0].ip;
    const { container } = render(<IpDetailModal ip={ip} onClose={vi.fn()} />);

    expect(document.body.textContent).toContain('/<img src=x onerror=alert(1)>?q=<svg onload=alert(2)>');
    expect(document.body.textContent).toContain('<script>alert("ua")</script>');
    expect(document.body.textContent).toContain('<img src=x onerror=alert("referer")>');
    expect(container.querySelectorAll('img, script')).toHaveLength(0);
  });

  it('shows the invalid-log error for a fixture where every line was skipped', () => {
    useAnalyzerStore.getState().setResult(stateLabFixtures.skippedLines);
    useAnalyzerStore.getState().setError('No valid log lines found. Is this an Apache/Nginx access log?');
    render(<UploadPage />);

    expect(screen.getByRole('alert').textContent).toBe('No valid log lines found. Is this an Apache/Nginx access log?');
  });
});
