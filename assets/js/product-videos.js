// Grab all videos
const clips = document.querySelectorAll('.autoplay-clip');

// Keep track of user-paused videos
const pausedByUser = new WeakSet();

clips.forEach(v => {
  v.muted = true;                 // required for autoplay
  v.removeAttribute('loop');      // we control looping manually

  // User pause/play detection
  v.addEventListener('pause', () => {
    if (!v.ended) pausedByUser.add(v);
  });
  v.addEventListener('play', () => {
    pausedByUser.delete(v);
  });

  // Custom loop with pause delay
  v.addEventListener('ended', () => {
    const delay = parseInt(v.dataset.pauseMs || '2000', 10);
    setTimeout(() => {
      if (pausedByUser.has(v)) return; // don’t override user pause
      v.currentTime = 0;
      v.play().catch(() => {});
    }, delay);
  });
});

// Play/pause only when in viewport
const io = new IntersectionObserver(entries => {
  entries.forEach(({ isIntersecting, target }) => {
    if (isIntersecting) {
      if (!pausedByUser.has(target)) {
        target.play().catch(() => {});
      }
    } else {
      target.pause();
    }
  });
}, {
  threshold: 0.25,          // 25% visible before playing
  rootMargin: '0px 0px'     // tweak if you want earlier start
});
clips.forEach(v => io.observe(v));

// One-time user gesture fallback (for Safari/iOS strict autoplay rules)
const unlock = () => {
  clips.forEach(v => v.play().catch(() => {}));
};
window.addEventListener('pointerdown', unlock, { once: true, passive: true });

// Respect prefers-reduced-motion
const reduceMotionQuery = matchMedia('(prefers-reduced-motion: reduce)');
const applyReduceMotion = e => {
  if (e.matches) {
    clips.forEach(v => v.pause());
  }
};
reduceMotionQuery.addEventListener('change', applyReduceMotion);
applyReduceMotion(reduceMotionQuery);
