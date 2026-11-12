// Copy-to-clipboard for revealed secret values. Loaded as an external script
// because the Content-Security-Policy forbids inline JavaScript.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-copy]");
  if (!btn || !navigator.clipboard) return;
  navigator.clipboard.writeText(btn.getAttribute("data-copy")).then(function () {
    var label = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(function () { btn.textContent = label; }, 1500);
  });
});
