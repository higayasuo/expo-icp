import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderError } from '../renderError';

describe('renderError', () => {
  let mockErrorElement: HTMLParagraphElement;

  beforeEach(() => {
    // Clear all mocks
    vi.clearAllMocks();

    // Create a mock error element
    mockErrorElement = document.createElement('p');
    mockErrorElement.id = 'error';
    document.body.appendChild(mockErrorElement);

    // Mock console.error
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    // Clean up the DOM
    if (mockErrorElement && mockErrorElement.parentNode) {
      mockErrorElement.parentNode.removeChild(mockErrorElement);
    }
  });

  it('should display error message when element exists', () => {
    const errorMessage = 'Test error message';
    renderError(errorMessage);

    expect(mockErrorElement.textContent).toBe(errorMessage);
    expect(mockErrorElement.style.display).toBe('block');
  });

  it('should hide error element when message is empty', () => {
    renderError('');

    expect(mockErrorElement.textContent).toBe('');
    expect(mockErrorElement.style.display).toBe('none');
  });

  it('should log error when element is not found', () => {
    // Remove the error element
    if (mockErrorElement && mockErrorElement.parentNode) {
      mockErrorElement.parentNode.removeChild(mockErrorElement);
    }

    renderError('Test error message');

    expect(console.error).toHaveBeenCalledWith('Error element not found');
  });
});
