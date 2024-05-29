import React, { useState } from 'react';
import { Carousel } from 'react-bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';

const Ourlandrover = () => {
  const [selectedIndex, setSelectedIndex] = useState(0);

  const handleSelect = (selectedIndex) => {
    setSelectedIndex(selectedIndex);
  };

  const handleThumbnailClick = (index) => {
    setSelectedIndex(index);
  };

  const images = [
    "/src/assets/img/portfolio/1.jpg",
    "/src/assets/img/portfolio/2.jpg",
    "/src/assets/img/portfolio/3.jpg"
  ];

  return (
    <div>
      <Carousel activeIndex={selectedIndex} onSelect={handleSelect} id="ourlandrover" interval={3000}>
        {images.map((src, index) => (
          <Carousel.Item key={index}>
            <img
              className="d-block w-100"
              src={src}
              alt={`Slide ${index + 1}`}
            />
          </Carousel.Item>
        ))}
      </Carousel>
      <div className="thumbnails mt-3">
        {images.map((src, index) => (
          <img
            key={index}
            src={src}
            alt={`Thumbnail ${index + 1}`}
            className={`thumbnail ${selectedIndex === index ? 'active' : ''}`}
            onClick={() => handleThumbnailClick(index)}
            style={{
              width: '100px',
              height: '60px',
              objectFit: 'cover',
              marginRight: '10px',
              cursor: 'pointer',
              border: selectedIndex === index ? '2px solid #007bff' : '2px solid transparent'
            }}
          />
        ))}
      </div>
    </div>
  );
};

export default Ourlandrover;
