import { LOGIN_BUTTON_ID, BACK_TO_APP_BUTTON_ID } from './constants';

/**
 * Parameters for preparing the buttons
 */
type PrepareButtonsResult = {
  /** The Internet Identity login button element */
  iiLoginButton: HTMLButtonElement;
  /** The back to app button element */
  backToAppButton: HTMLButtonElement;
};

/**
 * Prepares and validates the required buttons for the Internet Identity login flow
 * @returns An object containing the II login button and back to app button
 * @throws Error if required buttons are not found
 */
export const prepareButtons = (): PrepareButtonsResult => {
  const iiLoginButton = document.getElementById(
    LOGIN_BUTTON_ID,
  ) as HTMLButtonElement;
  const backToAppButton = document.getElementById(
    BACK_TO_APP_BUTTON_ID,
  ) as HTMLButtonElement;

  if (!iiLoginButton || !backToAppButton) {
    throw new Error('Required buttons not found');
  }

  return { iiLoginButton, backToAppButton };
};
