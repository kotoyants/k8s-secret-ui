// Loaded as an external script because the Content-Security-Policy forbids
// inline JavaScript (and htmx event filters, which need eval).

// Copy-to-clipboard for revealed secret values.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-copy]");
  if (!btn || !navigator.clipboard) return;
  navigator.clipboard.writeText(btn.getAttribute("data-copy")).then(function () {
    var label = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(function () { btn.textContent = label; }, 1500);
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
    var mask = document.createElement("span");
    mask.className = "masked";
    mask.textContent = "••••••••";
    target.replaceChildren(mask);
  }
});

// Tick the checkbox of every value that was revealed (per key or "Reveal all").
document.addEventListener("htmx:oobAfterSwap", function (e) {
  var id = e.target && e.target.id;
  if (!id) return;
  document.querySelectorAll(".reveal-toggle").forEach(function (box) {
    if (box.getAttribute("data-reveal-target") === id) box.checked = true;
  });
});
