document.getElementById("process-button").addEventListener("click", async () => {
    const form = document.getElementById("image-form");
    const formData = new FormData(form);

    const response = await fetch("/process", {
        method: "POST",
        body: formData
    });

    const result = await response.json();

    const responseDiv = document.getElementById("response");
    if (result.success) {
        
        responseDiv.innerHTML = `
            <p>Mensaje ocultado con éxito.</p>
            <p><strong>Contraseña:</strong> ${result.password}</p>
            <p><strong>Salt:</strong> ${result.salt}</p>
            <a id="download-link" href="${result.image_url}" download>
                <button type="button">Descargar Imagen</button>
            </a>
        `;

    } else {
        responseDiv.textContent = "Error: " + result.error;
    }
});