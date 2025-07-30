const API_URL = 'http://localhost:5000';

// Almacenar token y usuario
function setAuthData(token, user) {
    localStorage.setItem('authToken', token);
    localStorage.setItem('currentUser', JSON.stringify(user));
}

// Obtener token almacenado
export function getAuthToken() {
    return localStorage.getItem('authToken');
}

// Registro de usuario
export async function registerUser(nombre, email, password) {
    try {
        const response = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                nombre: nombre,
                email: email,
                password: password
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Error en el registro');
        }

        return data;
    } catch (error) {
        console.error('Error en registerUser:', error);
        throw error;
    }
}

// Inicio de sesión
export async function loginUser(email, password) {
    try {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: email,
                password: password
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Correo o contraseña incorrectos');
        }

        // Debug: Verificar datos recibidos
        console.log("Datos recibidos del servidor:", data);

        if (!data.token || !data.user) {
            throw new Error('Datos de autenticación incompletos');
        }

        // Almacenar token y datos del usuario
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('currentUser', JSON.stringify(data.user));
        
        // Debug: Verificar rol
        console.log("Rol del usuario:", data.user.role);
        
        return {
            token: data.token,
            user: data.user,
            redirectPath: data.user.role === 'admin' ? '/admin.html' : '/inicio.html'
        };
    } catch (error) {
        console.error('Error en login:', error);
        throw error;
    }
}

// Validar token
export async function validateToken() {
    const token = getAuthToken();
    if (!token) return false;
    try {
        const response = await fetch('http://127.0.0.1:5000/auth/validate-token', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        if (!response.ok) return false;
        const data = await response.json();
        return data.success || data.valid || true; // Ajusta según tu backend
    } catch (e) {
        return false;
    }
}

// Cerrar sesión
export function logout() {
    console.log('Ejecutando logout...'); // Para debug
    
    // Limpieza completa
    localStorage.clear();
    sessionStorage.clear();
    
    // Elimina todas las cookies
    document.cookie.split(';').forEach(cookie => {
        document.cookie = cookie.replace(/^ +/, '').replace(/=.*/, `=;expires=${new Date(0).toUTCString()};path=/`);
    });

    // Redirección forzada
    window.location.href = '/auth/login.html';
    window.location.reload(true);
}

// Obtener usuario actual
export function getCurrentUser() {
    const user = localStorage.getItem('currentUser');
    return user ? JSON.parse(user) : null;
}

// Verificar si es admin
export function isAdmin() {
    const user = getCurrentUser();
    if (!user) return false;
    return user.role === 'admin';
}

// Verificar autenticación
export function isAuthenticated() {
    return !!getAuthToken();
}

// ----------Solicitar recuperación de contraseña--------------------
export async function forgotPassword(email) {
    try {
        const response = await fetch(`${API_URL}/auth/forgot-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Error al solicitar recuperación');
        }

        return data;
    } catch (error) {
        console.error('Error en forgotPassword:', error);
        throw error;
    }
}

// Validar token de recuperación
export async function validateResetToken(token) {
    try {
        const response = await fetch(`${API_URL}/auth/validate-reset-token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ token })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Token inválido o expirado');
        }

        return data;
    } catch (error) {
        console.error('Error en validateResetToken:', error);
        throw error;
    }
}

// Restablecer contraseña
export async function resetPassword(token, newPassword) {
    try {
        const response = await fetch(`${API_URL}/auth/reset-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                token, 
                newPassword 
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Error al restablecer contraseña');
        }

        return data;
    } catch (error) {
        console.error('Error en resetPassword:', error);
        throw error;
    }
}


