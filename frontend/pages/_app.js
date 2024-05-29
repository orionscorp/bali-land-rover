import { useState, useEffect } from 'react';
import { I18nextProvider } from 'react-i18next';
import i18n from './i18n'; // Import your i18n initialization
import 'bootstrap/dist/css/bootstrap.min.css';
import '../styles/styles.css';

function MyApp({ Component, pageProps }) {
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    import("bootstrap/dist/js/bootstrap.bundle.min.js");
    setIsClient(true);
  }, []);

  if (!isClient) {
    return null; // or a loading spinner
  }

  return (
    <I18nextProvider i18n={i18n}>
      <Component {...pageProps} />
    </I18nextProvider>
  );
}

export default MyApp;
