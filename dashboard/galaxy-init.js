// Bridges galaxy.js (an ES module) into app.js (a classic script) via window globals,
// since the two can't import/export directly across module boundaries.
import { initGalaxy, updateGalaxy, resizeGalaxy } from "./galaxy.js";

document.addEventListener("DOMContentLoaded", () => {
  const container = document.getElementById("galaxy-canvas");
  initGalaxy(container, {
    onNodeClick: (project) => {
      if (window.openProjectFromGalaxy) window.openProjectFromGalaxy(project);
    },
  });
  window.__galaxyUpdate = updateGalaxy;
  window.__galaxyResize = resizeGalaxy;
});
