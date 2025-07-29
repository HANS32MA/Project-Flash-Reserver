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
    
    // Si es una ruta pública
    if (publicPaths.some(path => currentPath.endsWith(path))) {
        if (isAuthenticated()) {
            const user = getCurrentUser();
            window.location.href = user.role === 'admin' ? '/admin.html' : '/inicio.html';
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
        // 🔹 Si no es admin lo mandamos al login
        logout();
        window.location.href = '/auth/login.html';
    }
}

// Actualizar UI con datos del usuario
export function updateUserUI() {
    const user = getCurrentUser();
    if (!user) return;

    document.querySelectorAll('.user-name').forEach(el => {
        el.textContent = user.name;
    });
    
    document.querySelectorAll('.user-email').forEach(el => {
        el.textContent = user.email;
    });

    document.querySelectorAll('.admin-only').forEach(el => {
        el.style.display = isAdmin() ? 'block' : 'none';
    });
    
    document.querySelectorAll('.auth-only').forEach(el => {
        el.style.display = isAuthenticated() ? 'block' : 'none';
    });
    
    document.querySelectorAll('.guest-only').forEach(el => {
        el.style.display = isAuthenticated() ? 'none' : 'block';
    });
}

// Configurar eventos de autenticación
export function setupAuthEvents() {
    // Capturar botones logout por clase o ID
    const logoutButtons = [
        ...document.querySelectorAll('.logout-btn'),
        document.getElementById('logoutBtn'),
        document.getElementById('logoutBtnNav')
    ].filter(Boolean);

    logoutButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            if (confirm('¿Estás seguro de cerrar sesión?')) {
                logout();
                window.location.href = '/auth/login.html';
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
                
                const urlParams = new URLSearchParams(window.location.search);
                const redirect = urlParams.get('redirect');
                
                if (redirect) {
                    window.location.href = redirect;
                } else {
                    window.location.href = result.user.role === 'admin' ? '/admin.html' : '/inicio.html';
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
            
            if (password !== confirmPassword) {
                showError(registerForm, 'Las contraseñas no coinciden');
                return;
            }
            
            try {
                await registerUser(nombre, email, password);
                showSuccess(registerForm, '¡Registro exitoso! Redirigiendo...');
                setTimeout(() => {
                    window.location.href = '/auth/login.html';
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
        