document.getElementById("decrypt-button").addEventListener("click", async () => {
    const form = document.getElementById("decrypt-form");
    const formData = new FormData(form);

    const response = await fetch("/decrypt", {
        method: "POST",
        body: formData
    });

    const result = await response.json();

    const responseDiv = document.getElementById("response");
    if (result.success) {
        responseDiv.innerHTML = `<p><strong>Mensaje:</strong> ${result.message}</p>`;
    } else {
        responseDiv.textContent = "Error: " + result.error;
    }
});
