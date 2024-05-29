import { useEffect, useState } from 'react';
import Image from 'next/image';
import 'bootstrap/dist/css/bootstrap.min.css'; // Ensure Bootstrap CSS is imported

const Product = () => {
  const [modalSrc, setModalSrc] = useState('');
  const [modalAlt, setModalAlt] = useState('');
  const [modalNote, setModalNote] = useState('');
  const [modalClass, setModalClass] = useState('');

  useEffect(() => {
    import('bootstrap/dist/js/bootstrap.bundle.min.js');
  }, []);

  const handleShowModal = async (src, alt, note) => {
    setModalSrc(src);
    setModalAlt(alt);
    setModalNote(note);
    setModalClass('modal-book-open'); // Add the opening animation class
    const bootstrap = await import('bootstrap/dist/js/bootstrap.bundle.min.js');
    const modal = new bootstrap.Modal(document.getElementById('imageModal'));
    modal.show();
  };

  const handleHideModal = () => {
    setModalClass('modal-book-close'); // Add the closing animation class
    setTimeout(() => {
      const modalElement = document.getElementById('imageModal');
      const bootstrap = require('bootstrap/dist/js/bootstrap.bundle.min.js');
      const modal = bootstrap.Modal.getInstance(modalElement);
      modal.hide();
      setModalClass(''); // Remove the animation class after hiding the modal
    }, 600); // Match the animation duration
  };

  return (
    <section className="page-section bg-light" id="product">
      <div className="container">
        <div className="row">
          {[
            { src: '/src/assets/img/portfolio/1.jpg', alt: 'Threads', note: 'This is a note for Threads.' },
            { src: '/src/assets/img/portfolio/2.jpg', alt: 'Explore', note: 'This is a note for Explore.' },
            { src: '/src/assets/img/portfolio/3.jpg', alt: 'Finish', note: 'This is a note for Finish.' },
            { src: '/src/assets/img/portfolio/4.jpg', alt: 'Lines', note: 'This is a note for Lines.' },
            { src: '/src/assets/img/portfolio/5.jpg', alt: 'Southwest', note: 'This is a note for Southwest.' },
            { src: '/src/assets/img/portfolio/6.jpg', alt: 'Window', note: 'This is a note for Window.' },
          ].map((item, index) => (
            <div key={index} className="col-lg-4 col-sm-6 mb-4">
              <div className="portfolio-item">
                <div className="portfolio-link book" onClick={() => handleShowModal(item.src, item.alt, item.note)}>
                  <div className="gloss"></div>
                  <Image className="cover img-fluid" src={item.src} alt={item.alt} width={500} height={500} />
                  <div className="description">
                    <div className="description-text">
                      <h1>{item.alt}</h1>
                      <hr />
                      <p>{item.note}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Modal */}
      <div className={`modal fade ${modalClass}`} id="imageModal" tabIndex="-1" aria-labelledby="imageModalLabel" aria-hidden="true" onAnimationEnd={() => modalClass === 'modal-book-close' && handleHideModal()}>
        <div className="modal-dialog modal-dialog-centered">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title" id="imageModalLabel">{modalAlt}</h5>
              <button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="Close" onClick={handleHideModal}></button>
            </div>
            <div className="modal-body">
              <Image src={modalSrc} alt={modalAlt} layout="responsive" width={800} height={600} />
              <p className="mt-3">{modalNote}</p>
              <button className="btn btn-primary mt-3">Book Now</button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Product;
