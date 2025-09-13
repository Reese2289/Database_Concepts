$(document).ready(function(){
    $('.fade').slick({
      dots: true,                // Enable navigation dots
      infinite: true,            // Infinite looping
      speed: 500,                // Transition speed
      fade: true,                // Fade effect
      cssEase: 'linear',         // Smoother animation
      autoplay: true,            // Auto-slide
      autoplaySpeed: 3000        // Auto-slide delay
    });
  });
  