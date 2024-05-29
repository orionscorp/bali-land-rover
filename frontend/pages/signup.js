import Navbar from '../components/navbar';
import Footer from '../components/footer';
import { useState } from 'react';
import { useRouter } from 'next/router'; // Import useRouter from next/router

export default function SignUp() {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: ''
  });
  const router = useRouter(); // Initialize useRouter

  const handleSubmit = async (e) => {
    e.preventDefault();

    const response = await fetch('http://localhost:8080/signup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formData)
    });

    if (response.ok) {
      setFormData({
        username: '',
        email: '',
        password: ''
      });
      alert("Sign up successful!");
      router.push('/login'); // Navigate to the login page
    } else {
      const errorText = await response.text();
      alert(`Sign up failed: ${errorText}`);
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
      <section className="page-section" id="signup">
        <div className="container">
          <div className="text-center">
            <h2 className="section-heading text-uppercase">Sign Up</h2>
            <h3 className="section-subheading text-muted">
              Register to create an account.
            </h3>
          </div>
          <form id="signupForm" onSubmit={handleSubmit}>
            <div className="row justify-content-center align-items-center">
              <div className="col-md-6">
                <div className="form-group mb-4">
                  <input
                    className="form-control"
                    id="username"
                    type="text"
                    placeholder="Your Username *"
                    value={formData.username}
                    onChange={handleChange}
                    required
                  />
                </div>
                <div className="form-group mb-4">
                  <input
                    className="form-control"
                    id="email"
                    type="email"
                    placeholder="Your Email *"
                    value={formData.email}
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
                Sign Up
              </button>
            </div>
          </form>
        </div>
      </section>
      <Footer />
    </>
  );
}
