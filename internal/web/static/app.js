// Loaded as an external script because the Content-Security-Policy forbids
// inline JavaScript (and htmx event filters, which need eval).

// Double-click a revealed value ([data-copy] read-only textarea) to copy all of it.
document.addEventListener("dblclick", function (e) {
  var field = e.target.closest("[data-copy]");
  if (!field || !navigator.clipboard) return;
  field.select();
  navigator.clipboard.writeText(field.value).then(function () {
    field.classList.add("copied");
    setTimeout(function () { field.classList.remove("copied"); }, 1500);
  });
});

// Per-key reveal checkboxes (.reveal-toggle):
//   checked   → POST data-reveal-url; the response swaps the value in out-of-band
//               (the box is ticked only once the value has arrived, see below);
//   unchecked → view page: mask the value again; edit page: clear the textarea
//               back to "unchanged" unless the user has edited the value.
document.addEventListener("change", function (e) {
  var box = e.target;
  if (!box.classList || !box.classList.contains("reveal-toggle")) return;
  var target = document.getElementById(box.getAttribute("data-reveal-target"));
  if (box.checked) {
    box.checked = false;
    // No source element: htmx sends no form fields (the edit form must not be posted).
    htmx.ajax("POST", box.getAttribute("data-reveal-url"), { swap: "none" });
    return;
  }
  if (!target) return;
  if (target.tagName === "TEXTAREA") {
    if (target.value === target.defaultValue) {
      target.value = "";
      target.defaultValue = "";
    }
  } else {
    // View page: swap the value cell back to an empty masked field.
    var mask = document.createElement("textarea");
    mask.className = "secret-value";
    mask.readOnly = true;
    mask.rows = 1;
    mask.placeholder = "••••••••";
    mask.setAttribute("aria-label", box.getAttribute("aria-label").replace(/^Reveal /, "Value of ") + " (hidden)");
    target.replaceChildren(mask);
  }
});

// Tick the checkbox of every value that was revealed (per key or "Reveal").
document.addEventListener("htmx:oobAfterSwap", function (e) {
  var id = e.target && e.target.id;
  if (!id) return;
  document.querySelectorAll(".reveal-toggle").forEach(function (box) {
    if (box.getAttribute("data-reveal-target") === id) box.checked = true;
  });
  syncRevealAll();
});

// The "Reveal" button ([data-reveal-all]) is a toggle: once every per-key box is
// ticked it reads "Hide", and a click unticks each box (running the change
// handler above) instead of posting another reveal.
function allRevealed() {
  var boxes = document.querySelectorAll(".reveal-toggle");
  if (boxes.length === 0) return false;
  for (var i = 0; i < boxes.length; i++) {
    if (!boxes[i].checked) return false;
  }
  return true;
}

function syncRevealAll() {
  var hide = allRevealed();
  document.querySelectorAll("[data-reveal-all]").forEach(function (btn) {
    btn.textContent = hide ? "Hide" : "Reveal";
  });
}

document.addEventListener("change", function (e) {
  if (e.target.classList && e.target.classList.contains("reveal-toggle")) syncRevealAll();
});

// Capture phase, so htmx never sees the click (or the form submit it would trigger).
document.addEventListener("click", function (e) {
  if (!e.target.closest("[data-reveal-all]") || !allRevealed()) return;
  e.preventDefault();
  e.stopImmediatePropagation();
  document.querySelectorAll(".reveal-toggle").forEach(function (box) {
    box.checked = false;
    box.dispatchEvent(new Event("change", { bubbles: true }));
  });
}, true);

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", syncRevealAll);
} else {
  syncRevealAll();
}
