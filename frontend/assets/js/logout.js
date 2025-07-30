import { logout } from './auth.js';

function setupLogout() {
    // Configura ambos botones
    const logoutButtons = [
        document.getElementById('logoutBtn'),
        document.getElementById('logoutBtnNav')
    ];

    logoutButtons.forEach(btn => {
        if (btn) {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('Botón de logout clickeado'); // Para debug
                
                if (confirm('¿Estás seguro de cerrar sesión?')) {
                    logout();   
                    // Redirige a la página de login después de cerrar sesión
                    window.location.replace('/auth/login.html');
                }
            });
        }
    });
}

// Inicializa cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', setupLogout);