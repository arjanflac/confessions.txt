import {
  layoutWithLines,
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

  const atmosphericFragments = [
    "# testimony",
    "## timeline",
    "- disclosure deferred",
    "confession.md",
    "testimony.txt",
    "payload.tar.gz",
    "payload.age",
    "locked_artifact.jpg",
    "age passphrase private",
    "sha512(payload.age)",
    "audit commands",
    "verify --csha",
    "Base pointer",
    "Arweave archive",
    "local secret material",
    "public artifact material",
    "verification material",
    "STEG public != plaintext public",
    "NO HOSTED SEALING SERVICE",
    "STATIC VERIFIER"
  ];

  const leftFragments = [
    "# testimony",
    "confession.md",
    "plaintext stays local",
    "operator controls disclosure",
    "age passphrase private",
    "local secret material",
    "record before disclosure"
  ];

  const centerFragments = [
    "payload.tar.gz",
    "payload.age",
    "age encrypt",
    "HStego embed",
    "sha512(payload.age)",
    "sealed before publication",
    "CSHA"
  ];

  const rightFragments = [
    "ARTXID:t0hetLn4P34IVg_9A_HTU1mqfeFijpC5QVNcuk5KjzI",
    "0x1fc1b5ee05030fa8a0fa02f2776bee23298bb816cc584ebfa070b063ec5b7a18",
    "Base calldata prepared",
    "Arweave pointer generated",
    "locked_artifact.jpg",
    "static verifier output",
    "local audit commands"
  ];

  const lowerFragments = [
    "curl -fL -o locked_artifact.jpg",
    "python3 cli/confess.py extract --image locked_artifact.jpg",
    "python3 cli/confess.py verify --file payload.age --csha",
    "CSHA = sha512(payload.age)",
    "public record / private plaintext",
    "payload.age remains sealed"
  ];

  const noiseFragments = [
    "0xfa91166ca75492cf91fcb5293dd3b09b6b3cc133303c1bcb6618559097086c0f",
    "0x44464f7f52c6766fdda547a607bb628605c5dbd0690405aa3831e67de57424cd",
    "ftmS9HlhIA8jJ5S__hh6uU7pg5vM1W7yjD9NsFPc7cG",
    "2EpgPldBATXW3z2Abzejx59gSkSmq2pX3nRUyDM_vMo",
    "86a9d38be6d9fd0c261be03425faec1a8ba50006068ee43d",
    "e74ab0dce0e3f2a7036488c678a69356a6b954826e70fc0d",
    "8a84429c7faf4d5234803c14782020264563a315b6404a22"
  ];

  const orbitFragments = [
    "payload.age",
    "CSHA",
    "ARTXID",
    "STEG",
    "Base TX",
    "age",
    "HStego",
    "sha512",
    "locked_artifact.jpg"
  ];

  let width = 0;
  let height = 0;
  let dpr = 1;
  let visible = true;
  let frame = 0;
  let backLines = [];
  let wrapLines = [];
  let lowerLines = [];
  let noiseLines = [];
  let orbitLabels = [];
  let raf = 0;

  function font(size, weight) {
    return `${weight || 620} ${size}px "Nippo", "Courier New", monospace`;
  }

  function joinFragments(pool, repeat) {
    const out = [];
    for (let i = 0; i < repeat; i += 1) {
      for (let j = 0; j < pool.length; j += 1) {
        out.push(pool[(j + i) % pool.length]);
      }
    }
    return out.join("   ");
  }

  function makeLines(pool, options) {
    const prepared = prepareWithSegments(joinFragments(pool, options.repeat), options.font, {
      whiteSpace: "normal"
    });
    const layout = layoutWithLines(prepared, options.maxWidth, options.lineHeight);
    const source = layout.lines.length ? layout.lines : [];
    const generated = [];
    const max = Math.min(options.maxLines, source.length);

    for (let i = 0; i < max; i += 1) {
      const line = source[i];
      generated.push({
        text: line.text,
        width: line.width,
        font: options.font,
        x: options.x,
        y: options.y + i * options.lineHeight,
        speed: options.speed * (0.76 + ((i % 5) * 0.08)),
        alpha: options.alpha * (0.68 + ((i % 4) * 0.08)),
        color: options.color,
        phase: i * 37
      });
    }

    return generated;
  }

  function makeOrbitLabel(text, index, total, radiusX, radiusY, fontValue) {
    const prepared = prepareWithSegments(text, fontValue, { whiteSpace: "normal" });
    return {
      text,
      angle: (Math.PI * 2 * index) / total,
      radiusX,
      radiusY,
      width: measureNaturalWidth(prepared)
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

    const small = width < 520;
    const lineHeight = small ? 18 : 22;
    const baseFont = font(small ? 9 : 11, 600);
    const readableFont = font(small ? 10 : 12, 700);
    const atmosphericFont = font(small ? 8 : 10, 560);
    const centerX = width * 0.5;
    const swordWidth = Math.min(width * (small ? 0.34 : 0.28), small ? 140 : 210);
    const gutter = small ? 12 : 24;
    const leftWidth = Math.max(112, centerX - swordWidth * 0.6 - gutter);
    const rightX = centerX + swordWidth * 0.6 + gutter;
    const rightWidth = Math.max(112, width - rightX - gutter);
    const sideMax = Math.max(118, Math.min(leftWidth, rightWidth));

    backLines = [
      ...makeLines(atmosphericFragments, {
        repeat: small ? 9 : 15,
        font: atmosphericFont,
        lineHeight,
        maxWidth: width * 0.94,
        maxLines: Math.ceil(height / lineHeight) + 8,
        x: width * (small ? 0.06 : 0.03),
        y: small ? height * 0.08 : 24,
        speed: -0.035,
        alpha: small ? 0.2 : 0.16,
        color: "183, 189, 202"
      }),
      ...makeLines(noiseFragments, {
        repeat: small ? 4 : 8,
        font: font(small ? 8 : 10, 540),
        lineHeight: small ? 17 : 20,
        maxWidth: width * 0.9,
        maxLines: small ? 12 : 18,
        x: width * 0.05,
        y: height * (small ? 0.11 : 0.04),
        speed: 0.026,
        alpha: small ? 0.12 : 0.1,
        color: "94, 101, 120"
      }),
      ...makeLines([...atmosphericFragments, ...lowerFragments], {
        repeat: small ? 6 : 9,
        font: atmosphericFont,
        lineHeight: small ? 18 : 21,
        maxWidth: width * (small ? 0.86 : 0.8),
        maxLines: small ? 10 : 13,
        x: width * (small ? 0.08 : 0.1),
        y: height * (small ? 0.34 : 0.3),
        speed: 0.038,
        alpha: small ? 0.15 : 0.12,
        color: "183, 189, 202"
      })
    ];

    wrapLines = [
      ...makeLines(leftFragments, {
        repeat: small ? 6 : 10,
        font: baseFont,
        lineHeight: lineHeight + 2,
        maxWidth: sideMax,
        maxLines: Math.ceil(height / (lineHeight + 2)) + 4,
        x: small ? gutter + 10 : gutter,
        y: small ? height * 0.13 : 28,
        speed: -0.11,
        alpha: small ? 0.34 : 0.3,
        color: "183, 189, 202"
      }),
      ...makeLines(rightFragments, {
        repeat: small ? 6 : 10,
        font: baseFont,
        lineHeight: lineHeight + 2,
        maxWidth: rightWidth,
        maxLines: Math.ceil(height / (lineHeight + 2)) + 4,
        x: small ? rightX - 6 : rightX,
        y: small ? height * 0.18 : 50,
        speed: 0.12,
        alpha: small ? 0.32 : 0.28,
        color: "183, 189, 202"
      }),
      ...makeLines(centerFragments, {
        repeat: small ? 4 : 7,
        font: readableFont,
        lineHeight: lineHeight + 6,
        maxWidth: Math.max(150, width * (small ? 0.78 : 0.56)),
        maxLines: small ? 7 : 11,
        x: width * (small ? 0.12 : 0.16),
        y: height * (small ? 0.28 : 0.18),
        speed: -0.05,
        alpha: small ? 0.36 : 0.32,
        color: "238, 125, 115"
      })
    ];

    lowerLines = makeLines(lowerFragments, {
      repeat: small ? 5 : 9,
      font: readableFont,
      lineHeight: lineHeight + 7,
      maxWidth: Math.max(160, width * (small ? 0.72 : 0.64)),
      maxLines: small ? 5 : 8,
      x: width * (small ? 0.14 : 0.18),
      y: height * (small ? 0.52 : 0.58),
      speed: 0.045,
      alpha: small ? 0.42 : 0.42,
      color: "122, 215, 207"
    });

    const orbitFont = font(small ? 9 : 11, 700);
    orbitLabels = orbitFragments.map((label, index) => {
      return makeOrbitLabel(label, index, orbitFragments.length, width * (small ? 0.31 : 0.35), height * (small ? 0.24 : 0.28), orbitFont);
    });
  }

  function clear() {
    ctx.clearRect(0, 0, width, height);
  }

  function drawGrid(time) {
    ctx.save();
    ctx.globalAlpha = 0.16;
    ctx.strokeStyle = "rgba(240, 242, 247, 0.12)";
    ctx.lineWidth = 1;

    const gap = width < 520 ? 38 : 48;
    const offset = reduceMotion.matches ? 0 : (time * 0.004) % gap;

    for (let x = -gap + offset; x < width + gap; x += gap) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x + width * 0.12, height);
      ctx.stroke();
    }

    for (let y = -gap; y < height + gap; y += gap) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y + height * 0.04);
      ctx.stroke();
    }
    ctx.restore();
  }

  function drawLineSet(lines, time, multiplier) {
    ctx.save();
    ctx.textBaseline = "alphabetic";

    for (const line of lines) {
      const drift = reduceMotion.matches ? 0 : Math.sin((time * 0.00055) + line.phase) * 8;
      const travel = reduceMotion.matches ? 0 : (time * line.speed * 0.012) % 44;
      const x = line.x + drift + travel;
      const y = line.y;

      if (y < -28 || y > height + 28) continue;
      ctx.font = line.font;
      ctx.globalAlpha = line.alpha * multiplier;
      ctx.fillStyle = `rgba(${line.color}, 1)`;
      ctx.fillText(line.text, x, y);
    }

    ctx.restore();
  }

  function drawOrbit(time) {
    const cx = width * 0.5;
    const cy = height * 0.5;
    const speed = reduceMotion.matches ? 0 : time * 0.00009;

    ctx.save();
    ctx.textBaseline = "middle";
    ctx.font = font(width < 520 ? 9 : 11, 700);

    for (const label of orbitLabels) {
      const angle = label.angle + speed;
      const z = Math.sin(angle);
      const x = cx + Math.cos(angle) * label.radiusX - label.width / 2;
      const y = cy + z * label.radiusY;
      const alpha = 0.22 + ((z + 1) * 0.15);

      ctx.globalAlpha = alpha;
      ctx.fillStyle = z > 0 ? "rgba(238, 125, 115, 1)" : "rgba(217, 210, 191, 1)";
      ctx.fillText(label.text, x, y);
    }

    ctx.restore();
  }

  function drawVignette() {
    const edge = ctx.createLinearGradient(0, 0, width, 0);
    edge.addColorStop(0, "rgba(7, 8, 11, 0.72)");
    edge.addColorStop(0.16, "rgba(7, 8, 11, 0)");
    edge.addColorStop(0.84, "rgba(7, 8, 11, 0)");
    edge.addColorStop(1, "rgba(7, 8, 11, 0.72)");

    const lower = ctx.createLinearGradient(0, height * 0.45, 0, height);
    lower.addColorStop(0, "rgba(7, 8, 11, 0)");
    lower.addColorStop(1, "rgba(7, 8, 11, 0.34)");

    ctx.save();
    ctx.globalCompositeOperation = "source-over";
    ctx.fillStyle = edge;
    ctx.fillRect(0, 0, width, height);
    ctx.fillStyle = lower;
    ctx.fillRect(0, height * 0.45, width, height * 0.55);
    ctx.restore();
  }

  function draw(time) {
    clear();
    drawGrid(time);
    drawLineSet(backLines, time, 1);
    drawLineSet(wrapLines, time, 1);
    drawOrbit(time);
    drawLineSet(lowerLines, time, 1);
    drawVignette();
  }

  function loop(time) {
    if (visible) {
      draw(time || 0);
    }
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
