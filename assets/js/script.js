/* ================================
   THEME TOGGLE
================================ */

function applyTheme(themeName) {
    const isLight = themeName === "light";
    document.body.classList.toggle("light-mode", isLight);
    document.body.setAttribute("data-theme", themeName);
    localStorage.setItem("mg-theme", themeName);

    document.querySelectorAll(".theme-toggle").forEach((button) => {
        const icon = button.querySelector("i");
        if (!icon) return;

        if (isLight) {
            icon.classList.remove("fa-moon");
            icon.classList.add("fa-sun");
            button.setAttribute("aria-label", "Switch to dark mode");
        } else {
            icon.classList.remove("fa-sun");
            icon.classList.add("fa-moon");
            button.setAttribute("aria-label", "Switch to light mode");
        }
    });
}

const savedTheme = localStorage.getItem("mg-theme") || "dark";
applyTheme(savedTheme);

/* ================================
   NAVBAR SCROLL EFFECT
================================ */

const navbar = document.getElementById("navbar");

if (navbar) {
    window.addEventListener("scroll", () => {
        if (window.scrollY > 50) {
            navbar.classList.add("scrolled");
        } else {
            navbar.classList.remove("scrolled");
        }
    });
}

/* ================================
   MOBILE MENU
================================ */

function toggleMenu() {
    const navLinks = document.querySelector(".nav-links");
    if (navLinks) {
        navLinks.classList.toggle("active");
    }
}

/* ================================
   FILE UPLOAD PREVIEW
================================ */

const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");

if (dropZone && fileInput) {
    dropZone.addEventListener("click", (event) => {
        if (event.target.tagName !== "BUTTON") {
            fileInput.click();
        }
    });

    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) {
            const file = fileInput.files[0];
            const title = dropZone.querySelector("h3");
            if (title) {
                title.textContent = file.name;
            }
        }
    });

    dropZone.addEventListener("dragover", (event) => {
        event.preventDefault();
        dropZone.classList.add("dragover");
    });

    dropZone.addEventListener("dragleave", () => {
        dropZone.classList.remove("dragover");
    });

    dropZone.addEventListener("drop", (event) => {
        event.preventDefault();
        dropZone.classList.remove("dragover");

        const files = event.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            const title = dropZone.querySelector("h3");
            if (title) {
                title.textContent = files[0].name;
            }
        }
    });
}

/* ================================
   CLOSE MOBILE MENU
================================ */

document.querySelectorAll(".nav-links a").forEach((link) => {
    link.addEventListener("click", () => {
        const nav = document.querySelector(".nav-links");
        if (nav) {
            nav.classList.remove("active");
        }
    });
});

/* ================================
   THEME BUTTON HANDLER
================================ */

document.querySelectorAll(".theme-toggle").forEach((button) => {
    button.addEventListener("click", () => {
        const nextTheme = document.body.classList.contains("light-mode") ? "dark" : "light";
        applyTheme(nextTheme);
    });
});