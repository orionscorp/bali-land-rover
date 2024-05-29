import Link from 'next/link';
import { useState, useEffect } from 'react';
import Cookies from 'js-cookie'; // Import js-cookie
import '@fortawesome/fontawesome-free/css/all.min.css'; // Import FontAwesome CSS
import { useTranslation } from 'react-i18next'; // Import react-i18next

const Navbar = () => {
  const { t, i18n } = useTranslation(); // Initialize i18n translation
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState('');
  const [lang, setLang] = useState('en'); // State variable for language

  useEffect(() => {
    const storedUsername = localStorage.getItem('username');
    const email = localStorage.getItem('email');
    if (storedUsername && email) {
      setIsLoggedIn(true);
      setUsername(storedUsername);
    }

    // Set language from cookies or default to 'en'
    const savedLang = Cookies.get('lang') || 'en';
    setLang(savedLang);
    i18n.changeLanguage(savedLang); // Ensure i18n uses the correct language on load
  }, [i18n]);

  const toggleDropdown = () => {
    setDropdownOpen(!dropdownOpen);
  };

  const handleLogout = () => {
    localStorage.removeItem('username');
    localStorage.removeItem('email');
    setIsLoggedIn(false);
    setUsername('');
    // Optionally, redirect to the login page
    // window.location.href = '/login';
  };

  const handleLanguageChange = (selectedLang) => {
    setLang(selectedLang);
    Cookies.set('lang', selectedLang, {
      expires: 30, // 30 days expiration
      path: '/', // Root path
    });
    i18n.changeLanguage(selectedLang); // Change language
  };

  return (
    <nav className="navbar navbar-expand-lg navbar-dark fixed-top" id="mainNav">
      <div className="container">
        <Link href="/" className="navbar-brand">
          <img src="src/assets/img/vectorexports/navbar-logo.svg" alt="Logo" style={{ width: '150px', height: 'auto' }} />
        </Link>
        <button
          className="navbar-toggler"
          type="button"
          data-bs-toggle="collapse"
          data-bs-target="#navbarResponsive"
          aria-controls="navbarResponsive"
          aria-expanded="false"
          aria-label="Toggle navigation"
        >
          Menu
          <i className="fas fa-bars ms-1" />
        </button>
        <div className="collapse navbar-collapse" id="navbarResponsive">
          <ul className="navbar-nav text-uppercase ms-auto py-4 py-lg-0">
            <li className="nav-item">
              <Link href="/#product" className="nav-link">
                {t('PRODUCTS')}
              </Link>
            </li>
            <li className="nav-item">
              <Link href="/#destination" className="nav-link">
                {t('DESTINATIONS')}
              </Link>
            </li>
            <li className="nav-item">
              <Link href="/#about" className="nav-link">
                {t('ABOUT US')}
              </Link>
            </li>
            <li className="nav-item">
              <Link href="/#ourlandrover" className="nav-link">
                {t('OUR LAND ROVERS')}
              </Link>
            </li>
            <li className="nav-item dropdown">
              <a
                className="nav-link dropdown-toggle"
                href="#"
                id="navbarDropdown"
                role="button"
                aria-haspopup="true"
                aria-expanded={dropdownOpen ? "true" : "false"}
                onClick={toggleDropdown}
              >
                <i className="fas fa-user" />
              </a>
              <div
                className={`dropdown-menu ${dropdownOpen ? "show" : ""}`}
                aria-labelledby="navbarDropdown"
              >
                {isLoggedIn ? (
                  <p className="dropdown-item mb-0">{t('Welcome, {{username}}!', { username })}</p>
                ) : null}
                {!isLoggedIn ? (
                  <Link href="/login" className="dropdown-item">
                    {t('LOG IN')}
                  </Link>
                ) : (
                  <button className="dropdown-item mb-0" onClick={handleLogout}>
                    {t('LOG OUT')}
                  </button>
                )}
              </div>
            </li>
            {/* Language switcher */}
            <li className="nav-item">
              <button 
                className="nav-link" 
                onClick={() => handleLanguageChange(lang === 'en' ? 'id' : 'en')}
                aria-label={lang === 'en' ? 'Switch to Indonesian' : 'Switch to English'}
              >
                {lang === 'en' ? 'ID' : 'EN'}
              </button>
            </li>
          </ul>
        </div>  
      </div>
    </nav>
  );
};

export default Navbar;
