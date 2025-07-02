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

        // Generar token JWT (simulado)
        const token = generateToken(data.user.id);

        // Almacenar token y datos del usuario
        if (data.token && data.user) {
            setAuthData(data.token, data.user);
            
            // Devolver también información de redirección
            return {
                ...data,
                redirectPath: data.user.role === 'admin' 
                    ? '/frontend/admin.html' 
                    : '/frontend/inicio.html'
            };
        }
        
        return data;
    } catch (error) {
        console.error('Error en loginUser:', error);
        throw error;
    }
}

// Función simulada para generar token JWT
function generateToken(userId) {
    // En un entorno real, esto lo haría el servidor
    return `fake-jwt-token-for-user-${userId}`;
}

// Validar token
export async function validateToken() {
    try {
        const token = getAuthToken();
        if (!token) return null;

        const response = await fetch(`${API_URL}/auth/validate-token`, {
            method: 'GET',
            headers: {
                'Authorization': token
            }
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Token inválido');
        }

        return data;
    } catch (error) {
        console.error('Error al validar token:', error);
        logout();
        return null;
    }
}

// Cerrar sesión
export function logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('currentUser');
}

// Obtener usuario actual
export function getCurrentUser() {
    const user = localStorage.getItem('currentUser');
    return user ? JSON.parse(user) : null;
}

// Verificar si es admin
export function isAdmin() {
    const user = getCurrentUser();
    return user && user.role === 'admin';
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

// Obtener canchas disponibles
export async function getCanchasDisponibles() {
    try {
        const token = getAuthToken();
        if (!token) throw new Error('No autenticado');

        const response = await fetch(`${API_URL}/api/canchas`, {
            method: 'GET',
            headers: {
                'Authorization': token,
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Error al obtener canchas');
        }

        return data.canchas;
    } catch (error) {
        console.error('Error en getCanchasDisponibles:', error);
        throw error;
    }
}

// Obtener horarios disponibles
export async function getHorariosDisponibles(canchaId, fecha) {
    try {
        const token = getAuthToken();
        if (!token) throw new Error('No autenticado');

        const response = await fetch(`${API_URL}/api/horarios-disponibles?cancha_id=${canchaId}&fecha=${fecha}`, {
            method: 'GET',
            headers: {
                'Authorization': token,
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Error al obtener horarios');
        }

        return data.horarios_disponibles;
    } catch (error) {
        console.error('Error en getHorariosDisponibles:', error);
        throw error;
    }
}

// Crear reserva
export async function crearReserva(reservaData) {
    try {
        const token = getAuthToken();
        if (!token) throw new Error('No autenticado');

        const response = await fetch(`${API_URL}/api/reservas`, {
            method: 'POST',
            headers: {
                'Authorization': token,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(reservaData)
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Error al crear reserva');
        }

        return data;
    } catch (error) {
        console.error('Error en crearReserva:', error);
        throw error;
    }
}

// Obtener mis reservas
export async function getMisReservas() {
    try {
        const token = getAuthToken();
        if (!token) throw new Error('No autenticado');

        const response = await fetch(`${API_URL}/api/mis-reservas`, {
            method: 'GET',
            headers: {
                'Authorization': token,
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Error al obtener reservas');
        }

        return data.reservas;
    } catch (error) {
        console.error('Error en getMisReservas:', error);
        throw error;
    }
}

// Cancelar reserva
export async function cancelarReserva(reservaId) {
    try {
        const token = getAuthToken();
        if (!token) throw new Error('No autenticado');

        const response = await fetch(`${API_URL}/api/reservas/${reservaId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': token,
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Error al cancelar reserva');
        }

        return data;
    } catch (error) {
        console.error('Error en cancelarReserva:', error);
        throw error;
    }
}