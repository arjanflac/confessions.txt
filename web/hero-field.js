import {
  measureNaturalWidth,
  prepareWithSegments
} from "./vendor/pretext/dist/layout.js";

(function () {
  "use strict";

  const canvas = document.querySelector("[data-witness-field]");
  if (!canvas) return;

  const scene = document.querySelector("[data-hero-scene]");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const ctx = canvas.getContext("2d", { alpha: true });
  if (!ctx) return;

  const grayTokens = [
    "0", "1", "#", ".md", "0x", "sha", "age", "csha", "{ }", "[ ]",
    "--", "__", "/ /", "\\", "payload", "sealed", "local", "carrier"
  ];

  const coralTokens = ["#", ".md", "sha", "age", "0x", "sealed", "--csha"];
  const tealTokens = ["proof", "verify", "static"];

  let width = 0;
  let height = 0;
  let dpr = 1;
  let visible = true;
  let frame = 0;
  let raf = 0;
  let particles = [];

  function font(size, weight) {
    return `${weight || 650} ${size}px "Nippo", "Courier New", monospace`;
  }

  function seeded(index) {
    const x = Math.sin(index * 999.37 + 17.13) * 10000;
    return x - Math.floor(x);
  }

  function pick(pool, seed) {
    return pool[Math.floor(seed * pool.length) % pool.length];
  }

  function measure(text, fontValue) {
    const prepared = prepareWithSegments(text, fontValue, { whiteSpace: "normal" });
    return measureNaturalWidth(prepared);
  }

  function makeParticle(index, small) {
    const r1 = seeded(index + 1);
    const r2 = seeded(index + 11);
    const r3 = seeded(index + 23);
    const r4 = seeded(index + 41);
    const r5 = seeded(index + 67);
    const angle = r1 * Math.PI * 2;
    const radius = Math.sqrt(r2);
    const cx = width * 0.5;
    const cy = height * (small ? 0.38 : 0.47);
    const rx = width * (small ? 0.43 : 0.42);
    const ry = height * (small ? 0.32 : 0.34);

    let tone = "gray";
    if (r3 > 0.9) tone = "coral";
    if (r3 > 0.972) tone = "teal";

    const pool = tone === "coral" ? coralTokens : tone === "teal" ? tealTokens : grayTokens;
    const text = pick(pool, r4);
    const size = small
      ? 5.6 + r5 * (tone === "gray" ? 2.2 : 2.8)
      : 7 + r5 * (tone === "gray" ? 3.2 : 4);
    const fontValue = font(size, tone === "gray" ? 650 : 760);

    return {
      text,
      font: fontValue,
      width: measure(text, fontValue),
      x: cx + Math.cos(angle) * rx * radius,
      y: cy + Math.sin(angle) * ry * radius,
      drift: 1.5 + r4 * 4,
      speed: (r1 - 0.5) * 0.0007,
      phase: r2 * Math.PI * 2,
      alpha: tone === "gray"
        ? (small ? 0.075 : 0.065) + r5 * 0.07
        : tone === "coral"
          ? (small ? 0.12 : 0.1) + r5 * 0.075
          : 0.065 + r5 * 0.045,
      color: tone === "coral" ? "238, 125, 115" : tone === "teal" ? "122, 215, 207" : "183, 189, 202"
    };
  }

  function rebuild() {
    const rect = canvas.getBoundingClientRect();
    width = Math.max(1, Math.floor(rect.width));
    height = Math.max(1, Math.floor(rect.height));
    dpr = Math.min(2, window.devicePixelRatio || 1);

    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.imageSmoothingEnabled = false;

    const small = width < 520;
    const count = small ? 105 : 165;
    particles = Array.from({ length: count }, (_, index) => makeParticle(index, small));
  }

  function drawGrid(time) {
    ctx.save();
    ctx.globalAlpha = 0.065;
    ctx.strokeStyle = "rgba(240, 242, 247, 0.14)";
    ctx.lineWidth = 1;

    const gap = width < 520 ? 42 : 56;
    const offset = reduceMotion.matches ? 0 : (time * 0.0017) % gap;

    for (let x = -gap + offset; x < width + gap; x += gap) {
      ctx.beginPath();
      ctx.moveTo(Math.round(x), 0);
      ctx.lineTo(Math.round(x + width * 0.05), height);
      ctx.stroke();
    }

    for (let y = -gap; y < height + gap; y += gap) {
      ctx.beginPath();
      ctx.moveTo(0, Math.round(y));
      ctx.lineTo(width, Math.round(y + height * 0.02));
      ctx.stroke();
    }
    ctx.restore();
  }

  function drawDust(time) {
    ctx.save();
    ctx.textBaseline = "middle";

    for (const particle of particles) {
      const drift = reduceMotion.matches ? 0 : Math.sin(time * particle.speed + particle.phase) * particle.drift;
      const x = Math.round(particle.x + drift - particle.width / 2);
      const y = Math.round(particle.y + Math.cos(time * particle.speed + particle.phase) * particle.drift * 0.36);

      ctx.font = particle.font;
      ctx.globalAlpha = particle.alpha;
      ctx.fillStyle = `rgba(${particle.color}, 1)`;
      ctx.fillText(particle.text, x, y);
    }

    ctx.restore();
  }

  function drawVignette() {
    const edge = ctx.createLinearGradient(0, 0, width, 0);
    edge.addColorStop(0, "rgba(7, 8, 11, 0.82)");
    edge.addColorStop(0.18, "rgba(7, 8, 11, 0)");
    edge.addColorStop(0.82, "rgba(7, 8, 11, 0)");
    edge.addColorStop(1, "rgba(7, 8, 11, 0.82)");

    const lower = ctx.createLinearGradient(0, height * 0.5, 0, height);
    lower.addColorStop(0, "rgba(7, 8, 11, 0)");
    lower.addColorStop(1, "rgba(7, 8, 11, 0.48)");

    ctx.save();
    ctx.fillStyle = edge;
    ctx.fillRect(0, 0, width, height);
    ctx.fillStyle = lower;
    ctx.fillRect(0, height * 0.5, width, height * 0.5);
    ctx.restore();
  }

  function draw(time) {
    ctx.clearRect(0, 0, width, height);
    drawGrid(time);
    drawDust(time);
    drawVignette();
  }

  function loop(time) {
    if (visible) draw(time || 0);
    raf = window.requestAnimationFrame(loop);
  }

  function queueRebuild() {
    window.cancelAnimationFrame(frame);
    frame = window.requestAnimationFrame(() => {
      rebuild();
      draw(0);
    });
  }

  function setParallax(event) {
    if (!scene || reduceMotion.matches) return;
    const rect = scene.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const x = ((event.clientX - rect.left) / rect.width - 0.5) * 2;
    const y = ((event.clientY - rect.top) / rect.height - 0.5) * 2;
    scene.style.setProperty("--parallax-x", `${Math.max(-1, Math.min(1, x)) * 6}px`);
    scene.style.setProperty("--parallax-y", `${Math.max(-1, Math.min(1, y)) * 5}px`);
  }

  function resetParallax() {
    if (!scene) return;
    scene.style.setProperty("--parallax-x", "0px");
    scene.style.setProperty("--parallax-y", "0px");
  }

  const observer = new IntersectionObserver((entries) => {
    visible = entries.some((entry) => entry.isIntersecting);
  }, { threshold: 0.01 });

  observer.observe(canvas);
  window.addEventListener("resize", queueRebuild, { passive: true });
  if (scene) {
    scene.addEventListener("pointermove", setParallax, { passive: true });
    scene.addEventListener("pointerleave", resetParallax, { passive: true });
  }

  if (reduceMotion.addEventListener) {
    reduceMotion.addEventListener("change", () => {
      resetParallax();
      queueRebuild();
    });
  } else if (reduceMotion.addListener) {
    reduceMotion.addListener(() => {
      resetParallax();
      queueRebuild();
    });
  }

  const start = () => {
    rebuild();
    draw(0);
    raf = window.requestAnimationFrame(loop);
  };

  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(start);
  } else {
    start();
  }

  window.addEventListener("pagehide", () => {
    window.cancelAnimationFrame(raf);
  });
})();
