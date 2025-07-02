import { 
    loginUser, 
    registerUser, 
    forgotPassword, 
    getCurrentUser, 
    logout, 
    isAdmin,
    isAuthenticated,
    validateToken
} from './auth.js';

// Proteger rutas y manejar autenticación
export async function protectRoutes() {
    const publicPaths = ['/login.html', '/register.html', '/forgot.html', '/index.html'];
    const currentPath = window.location.pathname;
    
    // Si es una ruta pública, no hacer validación
    if (publicPaths.some(path => currentPath.endsWith(path))) {
        // Si el usuario ya está autenticado, redirigir según su rol
        if (isAuthenticated()) {
            const user = getCurrentUser();
            window.location.href = user.role === 'admin' ? '/admin.html' : '/profile.html';
        }
        return;
    }
    
    // Validar token para rutas protegidas
    const validation = await validateToken();
    if (!validation || !validation.success) {
        window.location.href = '/login.html?redirect=' + encodeURIComponent(currentPath);
        return;
    }
    
    // Verificar acceso a rutas de admin
    const adminPaths = ['/admin.html'];
    if (adminPaths.some(path => currentPath.endsWith(path)) && !isAdmin()) {
        window.location.href = '/403.html';
    }
}

// Actualizar UI con datos del usuario
export function updateUserUI() {
    const user = getCurrentUser();
    if (!user) return;

    // Actualizar elementos con clases específicas
    document.querySelectorAll('.user-name').forEach(el => {
        el.textContent = user.name;
    });
    
    document.querySelectorAll('.user-email').forEach(el => {
        el.textContent = user.email;
    });

    // Mostrar/ocultar elementos según rol
    document.querySelectorAll('.admin-only').forEach(el => {
        el.style.display = isAdmin() ? 'block' : 'none';
    });
    
    // Mostrar elementos de autenticación
    document.querySelectorAll('.auth-only').forEach(el => {
        el.style.display = isAuthenticated() ? 'block' : 'none';
    });
    
    document.querySelectorAll('.guest-only').forEach(el => {
        el.style.display = isAuthenticated() ? 'none' : 'block';
    });
}

// Configurar eventos de autenticación
export function setupAuthEvents() {
    // Logout
    document.querySelectorAll('.logout-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            if (confirm('¿Estás seguro de cerrar sesión?')) {
                logout();
                window.location.href = '/login.html';
            }
        });
    });
    
    // Login Form
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = loginForm.querySelector('#email').value;
            const password = loginForm.querySelector('#password').value;
            
            try {
                const result = await loginUser(email, password);
                
                // Redirigir según rol o parámetro redirect
                const urlParams = new URLSearchParams(window.location.search);
                const redirect = urlParams.get('redirect');
                
                if (redirect) {
                    window.location.href = redirect;
                } else {
                    window.location.href = result.user.role === 'admin' ? '/admin.html' : '/index.html';
                }
            } catch (error) {
                const errorElement = loginForm.querySelector('#message') || loginForm;
                showError(errorElement, error.message);
            }
        });
    }
    
    // Register Form
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const nombre = registerForm.querySelector('#nombre').value;
            const email = registerForm.querySelector('#email').value;
            const password = registerForm.querySelector('#password').value;
            const confirmPassword = registerForm.querySelector('#confirmPassword')?.value;
            
            // Validar contraseñas
            if (password !== confirmPassword) {
                showError(registerForm, 'Correo o contraseña incorrecto');
                return;
            }
            
            try {
                await registerUser(nombre, email, password);
                showSuccess(registerForm, '¡Registro exitoso! Redirigiendo...');
                setTimeout(() => {
                    window.location.href = '/admin.html';
                }, 2000);
            } catch (error) {
                showError(registerForm, error.message);
            }
        });
    }
}

// Mostrar mensaje de error
function showError(container, message) {
    const errorElement = container.querySelector('#message') || container;
    errorElement.innerHTML = `
        <div class="alert alert-danger">
            ${message}
        </div>
    `;
}

// Mostrar mensaje de éxito
function showSuccess(container, message) {
    const successElement = container.querySelector('#message') || container;
    successElement.innerHTML = `
        <div class="alert alert-success">
            ${message}
        </div>
    `;
}

// Inicialización
document.addEventListener('DOMContentLoaded', async () => {
    await protectRoutes();
    updateUserUI();
    setupAuthEvents();
});


