import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import Navbar from '../components/navbar';
import Footer from '../components/footer';

export default function Login() {
  const [formData, setFormData] = useState({ identifier: '', password: '' });
  const router = useRouter(); // Use Next.js useRouter for navigation

  const handleSubmit = async (e) => {
    e.preventDefault();

    const response = await fetch('http://localhost:8080/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formData)
    });

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('username', data.username);
      localStorage.setItem('email', data.email);
      setFormData({ identifier: '', password: '' });
      alert("Login successful!");
      router.push('/'); // Navigate to the index page

      // Listen for the route change complete event and reload the page
      router.events.on('routeChangeComplete', () => {
        window.location.reload();
      });
    } else {
      const errorText = await response.text();
      alert(`Login failed: ${errorText}`);
    }
  };

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.id]: e.target.value
    });
  };

  return (
    <>
      <Navbar />
      <section className="page-section" id="login">
        <div className="container">
          <div className="text-center">
            <h2 className="section-heading text-uppercase">Login</h2>
            <h3 className="section-subheading text-muted">
              Log in to your account.
            </h3>
          </div>
          <form id="loginForm" onSubmit={handleSubmit}>
            <div className="row justify-content-center align-items-center">
              <div className="col-md-6">
                <div className="form-group mb-4">
                  <input
                    className="form-control"
                    id="identifier"
                    type="text"
                    placeholder="Your Username or Email *"
                    value={formData.identifier}
                    onChange={handleChange}
                    required
                  />
                </div>
                <div className="form-group mb-4">
                  <input
                    className="form-control"
                    id="password"
                    type="password"
                    placeholder="Your Password *"
                    value={formData.password}
                    onChange={handleChange}
                    required
                  />
                </div>
              </div>
            </div>
            <div className="text-center">
              <button className="btn btn-primary btn-xl text-uppercase" type="submit">
                Sign In
              </button>
              <div className="mt-3">
                <button 
                  className="btn btn-secondary btn-xl text-uppercase" 
                  type="button" 
                  onClick={() => router.push('/signup')}
                >
                  Sign Up
                </button>
              </div>
            </div>
          </form>
        </div>
      </section>
      <Footer />
    </>
  );
}
