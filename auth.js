/* ===============================
   CyberRakshak AI - Auth Logic
   SIMPLIFIED - Server handles auth
   =============================== */

// LOGOUT only - everything else handled by Flask
function logoutUser() {
    window.location.href = "/logout";
}

// No protection checks - Flask-Login handles it
document.addEventListener("DOMContentLoaded", () => {
    console.log("Auth.js loaded - authentication handled by server");
});