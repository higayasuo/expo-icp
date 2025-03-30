import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderError } from '../renderError';

describe('renderError', () => {
  let mockErrorElement: { textContent: string; style: { display: string } };
  let mockQuerySelector: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    // Clear all mocks
    vi.clearAllMocks();

    // Create a mock error element
    mockErrorElement = {
      textContent: '',
      style: { display: '' },
    };

    // Mock document.querySelector
    mockQuerySelector = vi.fn().mockReturnValue(mockErrorElement);
    vi.stubGlobal('document', {
      querySelector: mockQuerySelector,
    });

    // Mock console.error
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  it('should display error message when element exists', () => {
    const errorMessage = 'Test error message';
    renderError(errorMessage);

    expect(mockQuerySelector).toHaveBeenCalledWith('#error');
    expect(mockErrorElement.textContent).toBe(errorMessage);
    expect(mockErrorElement.style.display).toBe('block');
  });

  it('should hide error element when message is empty', () => {
    renderError('');

    expect(mockQuerySelector).toHaveBeenCalledWith('#error');
    expect(mockErrorElement.textContent).toBe('');
    expect(mockErrorElement.style.display).toBe('none');
  });

  it('should log error when element is not found', () => {
    // Mock document.querySelector to return null
    mockQuerySelector.mockReturnValue(null);

    renderError('Test error message');

    expect(mockQuerySelector).toHaveBeenCalledWith('#error');
    expect(console.error).toHaveBeenCalledWith('Error element not found');
  });
});
