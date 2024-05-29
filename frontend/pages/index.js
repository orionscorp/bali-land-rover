import Navbar from '../components/navbar';
import Footer from '../components/footer';
import Products from '../components/products';
import Destinantions from '../components/destination';
import Ourlandrover from '../components/ourlandrover';

export default function Home() {
  return (
<>

  <meta charSet="utf-8" />
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1, shrink-to-fit=no"
  />
  <meta name="description" content="" />
  <meta name="author" content="" />
  <title>Bali Land Rover Tour</title>
  {/* Favicon*/}
  <link rel="icon" type="image/x-icon" href="assets/favicon.ico" />
  {/* Font Awesome icons (free version)*/}
  {/* Google fonts*/}
  <link
    href="https://fonts.googleapis.com/css?family=Montserrat:400,700"
    rel="stylesheet"
    type="text/css"
  />
  <link
    href="https://fonts.googleapis.com/css?family=Roboto+Slab:400,100,300,700"
    rel="stylesheet"
    type="text/css"
  />
  {/* Core theme CSS (includes Bootstrap)*/}
  <link href="styles/styles.css" rel="stylesheet" />

  <Navbar />
  {/* Masthead*/}
  <header className="masthead">
    <div className="container">
      <div className="masthead-subheading">Welcome To Our Studio!</div>
      <div className="masthead-heading text-uppercase">
        It's Nice To Meet You
      </div>
      <a className="btn btn-primary btn-xl text-uppercase" href="#abouthome">
        Tell Me More
      </a>
    </div>
  </header>
{/* about home */}
  <section className="page-section" id="abouthome">
    <div className="container">
      <div className="text-center">
        <h2 className="section-heading">“Bali Land Rover Tour innovatively explores Bali using a 4x4 Land Rover, 
        looking for a route and various experiences beyond the island's modernity and commercialism. 
        delivering care at a comfort, style, and safety level to guarantee an exciting and unforgettable trip.”</h2>
      </div>
    </div>
  </section>

  <Products />

  <Destinantions />

  {/* About*/}
  <section className="page-section" id="about">
    <div className="container">
      <div className="text-center">
        <h2 className="section-heading text-uppercase">About</h2>
        <h3 className="section-subheading text-muted">
          Lorem ipsum dolor sit amet consectetur.
        </h3>
      </div>
      <ul className="timeline">
        <li>
          <div className="timeline-image">
            <img
              className="rounded-circle img-fluid"
              src="src/assets/img/about/1.jpg"
              alt="..."
            />
          </div>
          <div className="timeline-panel">
            <div className="timeline-heading">
              <h4>2009-2011</h4>
              <h4 className="subheading">Our Humble Beginnings</h4>
            </div>
            <div className="timeline-body">
              <p className="text-muted">
                Lorem ipsum dolor sit amet, consectetur adipisicing elit. Sunt
                ut voluptatum eius sapiente, totam reiciendis temporibus qui
                quibusdam, recusandae sit vero unde, sed, incidunt et ea quo
                dolore laudantium consectetur!
              </p>
            </div>
          </div>
        </li>
        <li className="timeline-inverted">
          <div className="timeline-image">
            <img
              className="rounded-circle img-fluid"
              src="src/assets/img/about/2.jpg"
              alt="..."
            />
          </div>
          <div className="timeline-panel">
            <div className="timeline-heading">
              <h4>March 2011</h4>
              <h4 className="subheading">An Agency is Born</h4>
            </div>
            <div className="timeline-body">
              <p className="text-muted">
                Lorem ipsum dolor sit amet, consectetur adipisicing elit. Sunt
                ut voluptatum eius sapiente, totam reiciendis temporibus qui
                quibusdam, recusandae sit vero unde, sed, incidunt et ea quo
                dolore laudantium consectetur!
              </p>
            </div>
          </div>
        </li>
        <li>
          <div className="timeline-image">
            <img
              className="rounded-circle img-fluid"
              src="src/assets/img/about/3.jpg"
              alt="..."
            />
          </div>
          <div className="timeline-panel">
            <div className="timeline-heading">
              <h4>December 2015</h4>
              <h4 className="subheading">Transition to Full Service</h4>
            </div>
            <div className="timeline-body">
              <p className="text-muted">
                Lorem ipsum dolor sit amet, consectetur adipisicing elit. Sunt
                ut voluptatum eius sapiente, totam reiciendis temporibus qui
                quibusdam, recusandae sit vero unde, sed, incidunt et ea quo
                dolore laudantium consectetur!
              </p>
            </div>
          </div>
        </li>
        <li className="timeline-inverted">
          <div className="timeline-image">
            <img
              className="rounded-circle img-fluid"
              src="src/assets/img/about/4.jpg"
              alt="..."
            />
          </div>
          <div className="timeline-panel">
            <div className="timeline-heading">
              <h4>July 2020</h4>
              <h4 className="subheading">Phase Two Expansion</h4>
            </div>
            <div className="timeline-body">
              <p className="text-muted">
                Lorem ipsum dolor sit amet, consectetur adipisicing elit. Sunt
                ut voluptatum eius sapiente, totam reiciendis temporibus qui
                quibusdam, recusandae sit vero unde, sed, incidunt et ea quo
                dolore laudantium consectetur!
              </p>
            </div>
          </div>
        </li>
        <li className="timeline-inverted">
          <div className="timeline-image">
            <h4>
              Be Part
              <br />
              Of Our
              <br />
              Story!
            </h4>
          </div>
        </li>
      </ul>
    </div>
  </section>

  <Ourlandrover />

<Footer />

  {/* Bootstrap core JS*/}
  {/* Core theme JS*/}
  {/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **/}
  {/* * *                               SB Forms JS                               * **/}
  {/* * * Activate your form at https://startbootstrap.com/solution/contact-forms * **/}
  {/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **/}
</>

  );
}