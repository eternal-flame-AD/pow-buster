browser.storage.sync.get('offload_url').then((result) => {
    if (result.offload_url) {
        document.getElementById('offload_url').value = result.offload_url;
    } else {
        document.getElementById('offload_url').value = '';
    }
});
document.getElementById('options-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const offloadUrl = document.getElementById('offload_url').value;
    if (offloadUrl.trim()) {
        try {
            new URL(offloadUrl);
        } catch (error) {
            alert('Invalid URL: ' + error.message);
            return;
        }
        browser.storage.sync.set({ offload_url: offloadUrl });
        alert('Offload URL saved');
    } else {
        browser.storage.sync.set({ offload_url: offloadUrl });
        alert('Offload URL cleared');
    }
});