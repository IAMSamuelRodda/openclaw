// Replays image pastes that WebKitGTK delivers with an empty clipboardData.
// See src-tauri/src/clipboard_image.rs.
(() => {
  if (window.__openclawClipboardImage) {
    return;
  }
  window.__openclawClipboardImage = true;
  const focused = () => {
    let element = document.activeElement;
    while (element?.shadowRoot?.activeElement) {
      element = element.shadowRoot.activeElement;
    }
    return element ?? document.body;
  };
  window.addEventListener(
    "paste",
    (event) => {
      const data = event.clipboardData;
      if (!event.isTrusted || (data && (data.types.length > 0 || data.files.length > 0))) {
        return;
      }
      const target = focused();
      const route = location.pathname + location.search;
      window.__TAURI_INTERNALS__.invoke("clipboard_image").then(
        (png) => {
          if (!png) {
            return;
          }
          if (!target.isConnected || route !== location.pathname + location.search) {
            console.warn("Image paste dropped: the page changed before the image was ready.");
            return;
          }
          const bytes = Uint8Array.from(atob(png), (char) => char.charCodeAt(0));
          const transfer = new DataTransfer();
          transfer.items.add(new File([bytes], "image.png", { type: "image/png" }));
          target.dispatchEvent(
            new ClipboardEvent("paste", {
              clipboardData: transfer,
              bubbles: true,
              cancelable: true,
              composed: true,
            }),
          );
        },
        (error) => console.warn(`Image paste failed: ${error}`),
      );
    },
    true,
  );
})();
