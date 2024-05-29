import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

// Import language JSON files
import enTranslation from './locales/en.json';
import idTranslation from './locales/id.json';

// Initialize i18n
i18n
  .use(initReactI18next) // passes i18n down to react-i18next
  .init({
    resources: {
      en: {
        translation: enTranslation, // English translations
      },
      id: {
        translation: idTranslation, // Indonesian translations
      },
    },
    lng: 'en', // Set default language
    fallbackLng: 'en', // Fallback language if translation file is missing
    interpolation: {
      escapeValue: false, // React already safes from xss
    },
  });

export default i18n;
