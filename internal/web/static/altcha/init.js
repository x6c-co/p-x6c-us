// Loads the ALTCHA widget (its strict-CSP "external" build) and registers the
// SHA-256 worker, all served from this origin. Vendored from the altcha npm
// package; see README.md for the version and how to update it.
import "./altcha.min.js";

globalThis.$altcha.algorithms.set("SHA-256", () => new Worker("/static/altcha/sha.js"));
