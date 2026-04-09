import { layoutWithLines, measureLineStats, prepareWithSegments } from "./vendor/pretext/dist/layout.js";

const preparedCache = new WeakMap();
const TARGET_SELECTOR = "[data-pretext]";
const STYLE_ID = "pretext-balance-style";

let isApplying = false;
let queued = false;

function ensureStyles() {
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = `
    ${TARGET_SELECTOR}.pretext-balanced {
      width: fit-content;
      max-width: min(100%, var(--pretext-width, 100%));
      white-space: normal;
      text-wrap: unset;
    }

    ${TARGET_SELECTOR}[data-pretext="center"].pretext-balanced {
      margin-inline: auto;
    }

    ${TARGET_SELECTOR}.pretext-balanced .pretext-line {
      display: block;
    }
  `;
  document.head.appendChild(style);
}

function getSourceText(element) {
  if (element.dataset.pretextSource == null) {
    element.dataset.pretextSource = element.textContent || "";
  }
  return element.dataset.pretextSource;
}

function buildCanvasFont(style) {
  const parts = [];
  if (style.fontStyle && style.fontStyle !== "normal") parts.push(style.fontStyle);
  if (style.fontVariant && style.fontVariant !== "normal") parts.push(style.fontVariant);
  if (style.fontWeight) parts.push(style.fontWeight);
  if (style.fontStretch && style.fontStretch !== "100%") parts.push(style.fontStretch);
  parts.push(style.fontSize);
  parts.push(style.fontFamily);
  return parts.join(" ");
}

function getLineHeight(style) {
  const parsed = Number.parseFloat(style.lineHeight);
  if (Number.isFinite(parsed)) return parsed;
  const fontSize = Number.parseFloat(style.fontSize);
  return Number.isFinite(fontSize) ? fontSize * 1.2 : 19.2;
}

function getAvailableWidth(element, style) {
  const parent = element.parentElement;
  let width = parent
    ? parent.getBoundingClientRect().width
    : element.getBoundingClientRect().width;

  const parsedMaxWidth = Number.parseFloat(style.maxWidth);
  if (Number.isFinite(parsedMaxWidth)) {
    width = Math.min(width, parsedMaxWidth);
  }

  return Math.max(0, Math.floor(width));
}

function getPrepared(element, text, font) {
  const cached = preparedCache.get(element);
  if (cached && cached.text === text && cached.font === font) {
    return cached.prepared;
  }
  const prepared = prepareWithSegments(text, font);
  preparedCache.set(element, { text, font, prepared });
  return prepared;
}

function findBalancedWidth(prepared, availableWidth, targetLineCount) {
  if (targetLineCount <= 1) return availableWidth;

  let low = 1;
  let high = availableWidth;
  let best = availableWidth;

  while (high - low > 1) {
    const mid = Math.floor((low + high) / 2);
    const { lineCount } = measureLineStats(prepared, mid);
    if (lineCount <= targetLineCount) {
      best = mid;
      high = mid;
    } else {
      low = mid;
    }
  }

  return best;
}

function materializeLines(element, lines, balancedWidth, sourceText) {
  const fragment = document.createDocumentFragment();
  lines.forEach((line) => {
    const span = document.createElement("span");
    span.className = "pretext-line";
    span.textContent = line.text;
    fragment.appendChild(span);
  });

  element.classList.add("pretext-balanced");
  element.style.setProperty("--pretext-width", `${Math.ceil(balancedWidth)}px`);
  element.setAttribute("aria-label", sourceText.trim());
  element.replaceChildren(fragment);
}

function renderElement(element) {
  const sourceText = getSourceText(element);
  if (!sourceText.trim()) return;

  const style = getComputedStyle(element);
  const availableWidth = getAvailableWidth(element, style);
  if (!availableWidth) return;

  const font = buildCanvasFont(style);
  const prepared = getPrepared(element, sourceText, font);
  const lineHeight = getLineHeight(style);
  const initialStats = measureLineStats(prepared, availableWidth);
  const targetLineCount = Math.max(1, initialStats.lineCount || 1);
  const balancedWidth = findBalancedWidth(prepared, availableWidth, targetLineCount);
  const { lines } = layoutWithLines(prepared, balancedWidth, lineHeight);

  materializeLines(element, lines, balancedWidth, sourceText);
}

function renderAll(root = document) {
  if (isApplying) return;
  isApplying = true;
  try {
    const elements = root.querySelectorAll(TARGET_SELECTOR);
    elements.forEach((element) => renderElement(element));
  } finally {
    isApplying = false;
  }
}

function queueRender(root = document) {
  if (queued) return;
  queued = true;
  requestAnimationFrame(() => {
    queued = false;
    renderAll(root);
  });
}

function watchMutations() {
  const observer = new MutationObserver((mutations) => {
    if (isApplying) return;
    for (const mutation of mutations) {
      if (mutation.type !== "childList") continue;
      for (const node of mutation.addedNodes) {
        if (!(node instanceof Element)) continue;
        if (node.matches(TARGET_SELECTOR) || node.querySelector(TARGET_SELECTOR)) {
          queueRender(document);
          return;
        }
      }
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

function init() {
  ensureStyles();
  const triggerRender = () => queueRender(document);

  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(triggerRender);
  } else {
    triggerRender();
  }

  window.addEventListener("resize", triggerRender, { passive: true });
  watchMutations();
}

init();
