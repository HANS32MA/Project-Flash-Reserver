import { getAuthToken, getCurrentUser, logout, isAdmin, validateToken } from './auth.js';

// Configuración global
const API_BASE = 'http://localhost:5000/api';

// Función para hacer peticiones HTTP con token
async function fetchData(endpoint, options = {}) {
    /*const token = getAuthToken();
    if (!token) {
        // Redirigir o mostrar error
        return;
    }

    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}` // <-- Aquí debe ir el token
        }
    };

    try {
        const response = await fetch(`${API_BASE}/${endpoint}`, { ...defaultOptions, ...options });

        if (response.status === 401) {
            // Token inválido o expirado
            throw new Error('Token inválido o expirado');
        }

        if (!response.ok) {
            let error = {};
            try {
                error = await response.json();
            } catch (e) {
                // Si no es JSON, usar status
                error.message = `Error ${response.status}`;
            }
            throw new Error(error.message || `Error ${response.status}`);
        }

        return response.json();
    } catch (error) {
        // Solo aquí se maneja el logout/redirección si es necesario
        if (
            error.message === 'No hay token de autenticación' ||
            error.message === 'Token inválido o expirado'
        ) {
            logout();
            window.location.href = '/auth/login.html';
            return; // Opcional: puedes lanzar el error si quieres manejarlo arriba
        }
        console.error(`Error en fetchData para ${endpoint}:`, error);
        throw error;
    }
}*/

// ===== FUNCIONES DEL DASHBOARD =====

async function loadDashboardStats() {
    try {
        const data = await fetchData('dashboard/stats');
        const todayReservations = document.getElementById('todayReservations');
        const activeCourts = document.getElementById('activeCourts');
        const totalUsers = document.getElementById('totalUsers');
        const pendingReservations = document.getElementById('pendingReservations');
        
        if (todayReservations) todayReservations.textContent = data.todayReservations || 0;
        if (activeCourts) activeCourts.textContent = data.activeCourts || 0;
        if (totalUsers) totalUsers.textContent = data.totalUsers || 0;
        if (pendingReservations) pendingReservations.textContent = data.pendingReservations || 0;
    } catch (err) {
        console.error('Error al cargar dashboard/stats:', err.message);
    }
}

// ===== FUNCIONES PARA USUARIOS =====

async function loadUsuarios() {
    try {
        const response = await fetchData('users');
        const tbody = document.querySelector('#usersTable tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        response.users.forEach(u => {
            tbody.innerHTML += `
                <tr>
                    <td>${u.id}</td>
                    <td>${u.name}</td>
                    <td>${u.email}</td>
                    <td>${u.document || '-'}</td>
                    <td>${u.role_text}</td>
                    <td>${u.reservations_count || 0}</td>
                    <td>${u.registration_date || '-'}</td>
                    <td>
                        <button class="btn btn-sm btn-warning btn-edit-user" data-id="${u.id}">
                            <i class="bi bi-pencil"></i>
                        </button>
                        <button class="btn btn-sm btn-danger btn-delete-user" data-id="${u.id}">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                </tr>`;
        });
        
        // Agregar event listeners para botones
        setupUserEventListeners();
    } catch (err) {
        console.error('Error al cargar users:', err.message);
    }
}

function setupUserEventListeners() {
    // Botones editar usuario
    document.querySelectorAll('.btn-edit-user').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const userId = e.target.closest('button').dataset.id;
            editUser(userId);
        });
    });
    
    // Botones eliminar usuario
    document.querySelectorAll('.btn-delete-user').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const userId = e.target.closest('button').dataset.id;
            deleteUser(userId);
        });
    });
}

async function editUser(userId) {
    try {
        const user = await fetchData(`users/${userId}`);
        // Llenar modal de edición
        document.getElementById('editUserId').value = user.id;
        document.getElementById('editUserName').value = user.name;
        document.getElementById('editUserEmail').value = user.email;
        document.getElementById('editUserDocument').value = user.document || '';
        document.getElementById('editUserRole').value = user.role;
        
        // Mostrar modal
        const modal = new bootstrap.Modal(document.getElementById('editUserModal'));
        modal.show();
    } catch (err) {
        alert(`Error al cargar usuario: ${err.message}`);
    }
}

async function updateUser() {
    try {
        const userId = document.getElementById('editUserId').value;
        const userData = {
            name: document.getElementById('editUserName').value,
            email: document.getElementById('editUserEmail').value,
            document: document.getElementById('editUserDocument').value,
            role: document.getElementById('editUserRole').value
        };
        
        await fetchData(`users/${userId}`, {
            method: 'PUT',
            body: JSON.stringify(userData)
        });
        
        alert('✅ Usuario actualizado correctamente');
        bootstrap.Modal.getInstance(document.getElementById('editUserModal')).hide();
        loadUsuarios();
    } catch (err) {
        alert(`❌ Error al actualizar usuario: ${err.message}`);
    }
}

async function deleteUser(userId) {
    if (!confirm('¿Estás seguro de que quieres eliminar este usuario?')) return;
    
    try {
        await fetchData(`users/${userId}`, { method: 'DELETE' });
        alert('✅ Usuario eliminado correctamente');
        loadUsuarios();
    } catch (err) {
        alert(`❌ Error al eliminar usuario: ${err.message}`);
    }
}

// ===== FUNCIONES PARA CANCHAS =====

async function loadCanchas() {
    try {
        const response = await fetchData('courts');
        const tbody = document.querySelector('#courtsTable tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        response.courts.forEach(c => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${c.id}</td>
                <td>${c.name}</td>
                <td>${c.type || '-'}</td>
                <td>${c.surface || '-'}</td>
                <td>${c.covered ? 'Sí' : 'No'}</td>
                <td>$${c.price}</td>
                <td>${c.status_text}</td>
                <td>
                    <button class="btn btn-sm btn-warning btn-edit-court" data-id="${c.id}">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button class="btn btn-sm btn-danger btn-delete-court" data-id="${c.id}">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
        
        setupCourtEventListeners();
    } catch (err) {
        console.error('Error al cargar courts:', err.message);
    }
}

function setupCourtEventListeners() {
    // Botones editar cancha
    document.querySelectorAll('.btn-edit-court').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const courtId = e.target.closest('button').dataset.id;
            editCourt(courtId);
        });
    });
    
    // Botones eliminar cancha
    document.querySelectorAll('.btn-delete-court').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const courtId = e.target.closest('button').dataset.id;
            deleteCourt(courtId);
        });
    });
}

async function editCourt(courtId) {
    try {
        const court = await fetchData(`courts/${courtId}`);
        // Llenar modal de edición
        document.getElementById('editCourtId').value = court.id;
        document.getElementById('editCourtName').value = court.name;
        document.getElementById('editCourtDescription').value = court.description || '';
        document.getElementById('editCourtType').value = court.type || '';
        document.getElementById('editCourtSurface').value = court.surface || '';
        document.getElementById('editCourtCovered').checked = court.covered;
        document.getElementById('editCourtCapacity').value = court.capacity || '';
        document.getElementById('editCourtPrice').value = court.price;
        document.getElementById('editCourtStatus').value = court.status;
        
        // Mostrar modal
        const modal = new bootstrap.Modal(document.getElementById('editCourtModal'));
        modal.show();
    } catch (err) {
        alert(`Error al cargar cancha: ${err.message}`);
    }
}

async function updateCourt() {
    try {
        const courtId = document.getElementById('editCourtId').value;
        const courtData = {
            name: document.getElementById('editCourtName').value,
            description: document.getElementById('editCourtDescription').value,
            type: document.getElementById('editCourtType').value,
            surface: document.getElementById('editCourtSurface').value,
            covered: document.getElementById('editCourtCovered').checked,
            capacity: parseInt(document.getElementById('editCourtCapacity').value) || null,
            price: parseFloat(document.getElementById('editCourtPrice').value),
            status: document.getElementById('editCourtStatus').value
        };
        
        await fetchData(`courts/${courtId}`, {
            method: 'PUT',
            body: JSON.stringify(courtData)
        });
        
        alert('✅ Cancha actualizada correctamente');
        bootstrap.Modal.getInstance(document.getElementById('editCourtModal')).hide();
        loadCanchas();
    } catch (err) {
        alert(`❌ Error al actualizar cancha: ${err.message}`);
    }
}

async function deleteCourt(courtId) {
    if (!confirm('¿Estás seguro de que quieres eliminar esta cancha?')) return;
    
    try {
        await fetchData(`courts/${courtId}`, { method: 'DELETE' });
        alert('✅ Cancha eliminada correctamente');
        loadCanchas();
    } catch (err) {
        alert(`❌ Error al eliminar cancha: ${err.message}`);
    }
}

// ===== FUNCIONES PARA RESERVAS =====

async function loadReservas() {
    try {
        const response = await fetchData('reservations');
        const tbody = document.querySelector('#reservationsTable tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        response.reservations.forEach(r => {
            tbody.innerHTML += `
                <tr>
                    <td>${r.id}</td>
                    <td>${r.court_name}</td>
                    <td>${r.user_name}</td>
                    <td>${r.date} ${r.time}</td>
                    <td>${r.total}</td>
                    <td>${r.status_text}</td>
                    <td>
                        <button class="btn btn-sm btn-warning btn-edit-reservation" data-id="${r.id}">
                            <i class="bi bi-pencil"></i>
                        </button>
                        <button class="btn btn-sm btn-info btn-view-reservation" data-id="${r.id}">
                            <i class="bi bi-eye"></i>
                        </button>
                    </td>
                </tr>`;
        });
        
        setupReservationEventListeners();
    } catch (err) {
        console.error('Error al cargar reservations:', err.message);
    }
}

function setupReservationEventListeners() {
    // Botones editar reserva
    document.querySelectorAll('.btn-edit-reservation').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const reservationId = e.target.closest('button').dataset.id;
            editReservation(reservationId);
        });
    });
    
    // Botones ver reserva
    document.querySelectorAll('.btn-view-reservation').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const reservationId = e.target.closest('button').dataset.id;
            viewReservation(reservationId);
        });
    });
}

async function editReservation(reservationId) {
    try {
        const reservation = await fetchData(`reservations/${reservationId}`);
        // Llenar modal de edición
        document.getElementById('editReservationId').value = reservation.id;
        document.getElementById('editReservationStatus').value = reservation.status;
        
        // Mostrar modal
        const modal = new bootstrap.Modal(document.getElementById('editReservationModal'));
        modal.show();
    } catch (err) {
        alert(`Error al cargar reserva: ${err.message}`);
    }
}

async function updateReservation() {
    try {
        const reservationId = document.getElementById('editReservationId').value;
        const reservationData = {
            status: document.getElementById('editReservationStatus').value
        };
        
        await fetchData(`reservations/${reservationId}`, {
            method: 'PUT',
            body: JSON.stringify(reservationData)
        });
        
        alert('✅ Reserva actualizada correctamente');
        bootstrap.Modal.getInstance(document.getElementById('editReservationModal')).hide();
        loadReservas();
    } catch (err) {
        alert(`❌ Error al actualizar reserva: ${err.message}`);
    }
}

async function viewReservation(reservationId) {
    try {
        const reservation = await fetchData(`reservations/${reservationId}`);
        // Mostrar detalles en modal
        document.getElementById('viewReservationDetails').innerHTML = `
            <p><strong>ID:</strong> ${reservation.id}</p>
            <p><strong>Cancha:</strong> ${reservation.court_name}</p>
            <p><strong>Usuario:</strong> ${reservation.user_name}</p>
            <p><strong>Fecha:</strong> ${reservation.date}</p>
            <p><strong>Hora:</strong> ${reservation.time}</p>
            <p><strong>Estado:</strong> ${reservation.status}</p>
            <p><strong>Total:</strong> $${reservation.total}</p>
        `;
        
        const modal = new bootstrap.Modal(document.getElementById('viewReservationModal'));
        modal.show();
    } catch (err) {
        alert(`Error al cargar reserva: ${err.message}`);
    }
}

// ===== FUNCIONES PARA HORARIOS =====

async function loadHorarios() {
    try {
        const response = await fetchData('schedules');
        const tbody = document.querySelector('#schedulesTable tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        response.schedules.forEach(s => {
            tbody.innerHTML += `
                <tr>
                    <td>${s.id}</td>
                    <td>${s.court_name}</td>
                    <td>${s.day}</td>
                    <td>${s.start_time} - ${s.end_time}</td>
                    <td>${s.available_text}</td>
                    <td>${s.created_date}</td>
                    <td>
                        <button class="btn btn-sm btn-danger btn-delete-schedule" data-id="${s.id}">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                </tr>`;
        });
        
        setupScheduleEventListeners();
    } catch (err) {
        console.error('Error al cargar schedules:', err.message);
    }
}

function setupScheduleEventListeners() {
    // Botones eliminar horario
    document.querySelectorAll('.btn-delete-schedule').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const scheduleId = e.target.closest('button').dataset.id;
            deleteSchedule(scheduleId);
        });
    });
}

async function deleteSchedule(scheduleId) {
    if (!confirm('¿Estás seguro de que quieres eliminar este horario?')) return;
    
    try {
        await fetchData(`schedules/${scheduleId}`, { method: 'DELETE' });
        alert('✅ Horario eliminado correctamente');
        loadHorarios();
    } catch (err) {
        alert(`❌ Error al eliminar horario: ${err.message}`);
    }
}

// ===== FUNCIONES PARA COMENTARIOS =====

async function loadComentarios() {
    try {
        const response = await fetchData('comments');
        const tbody = document.querySelector('#commentsTable tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        response.comments.forEach(c => {
            tbody.innerHTML += `
                <tr>
                    <td>${c.id}</td>
                    <td>${c.court_name}</td>
                    <td>${c.user_name}</td>
                    <td>${'⭐'.repeat(c.rating)}</td>
                    <td>${c.comment}</td>
                    <td>${c.status_text}</td>
                    <td>${c.comment_date}</td>
                    <td>
                        <button class="btn btn-sm btn-warning btn-edit-comment" data-id="${c.id}">
                            <i class="bi bi-pencil"></i>
                        </button>
                        <button class="btn btn-sm btn-danger btn-delete-comment" data-id="${c.id}">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                </tr>`;
        });
        
        setupCommentEventListeners();
    } catch (err) {
        console.error('Error al cargar comments:', err.message);
    }
}

function setupCommentEventListeners() {
    // Botones editar comentario
    document.querySelectorAll('.btn-edit-comment').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const commentId = e.target.closest('button').dataset.id;
            editComment(commentId);
        });
    });
    
    // Botones eliminar comentario
    document.querySelectorAll('.btn-delete-comment').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const commentId = e.target.closest('button').dataset.id;
            deleteComment(commentId);
        });
    });
}

async function editComment(commentId) {
    try {
        const comment = await fetchData(`comments/${commentId}`);
        // Llenar modal de edición
        document.getElementById('editCommentId').value = comment.id;
        document.getElementById('editCommentStatus').value = comment.status;
        document.getElementById('editCommentResponse').value = comment.admin_response || '';
        
        // Mostrar modal
        const modal = new bootstrap.Modal(document.getElementById('editCommentModal'));
        modal.show();
    } catch (err) {
        alert(`Error al cargar comentario: ${err.message}`);
    }
}

async function updateComment() {
    try {
        const commentId = document.getElementById('editCommentId').value;
        const commentData = {
            status: document.getElementById('editCommentStatus').value,
            admin_response: document.getElementById('editCommentResponse').value
        };
        
        await fetchData(`comments/${commentId}`, {
            method: 'PUT',
            body: JSON.stringify(commentData)
        });
        
        alert('✅ Comentario actualizado correctamente');
        bootstrap.Modal.getInstance(document.getElementById('editCommentModal')).hide();
        loadComentarios();
    } catch (err) {
        alert(`❌ Error al actualizar comentario: ${err.message}`);
    }
}

async function deleteComment(commentId) {
    if (!confirm('¿Estás seguro de que quieres eliminar este comentario?')) return;
    
    try {
        await fetchData(`comments/${commentId}`, { method: 'DELETE' });
        alert('✅ Comentario eliminado correctamente');
        loadComentarios();
    } catch (err) {
        alert(`❌ Error al eliminar comentario: ${err.message}`);
    }
}

// ===== FUNCIONES DE CREACIÓN =====

async function createCourt() {
    try {
        // Verificar que todos los elementos existan antes de acceder a ellos
        const courtName = document.getElementById('courtName');
        const courtDescription = document.getElementById('courtDescription');
        const courtType = document.getElementById('courtType');
        const courtSurface = document.getElementById('courtSurface');
        const courtCovered = document.getElementById('courtCovered');
        const courtCapacity = document.getElementById('courtCapacity');
        const courtPrice = document.getElementById('courtPrice');
        const courtImages = document.getElementById('courtImages');
        
        if (!courtName || !courtType || !courtSurface || !courtCapacity || !courtPrice) {
            throw new Error('Faltan campos requeridos en el formulario');
        }
        
        const courtData = {
            name: courtName.value,
            description: courtDescription ? courtDescription.value : '',
            type: courtType.value,
            surface: courtSurface.value,
            covered: courtCovered ? courtCovered.checked : false,
            capacity: parseInt(courtCapacity.value) || 0,
            price: parseFloat(courtPrice.value) || 0,
            image: courtImages ? courtImages.value : null
        };
        
        await fetchData('courts', {
            method: 'POST',
            body: JSON.stringify(courtData)
        });
        
        alert('✅ Cancha creada correctamente');
        // Limpiar formulario
        const addCourtForm = document.getElementById('addCourtForm');
        if (addCourtForm) {
            addCourtForm.reset();
        }
        // Cerrar modal
        const addCourtModal = document.getElementById('addCourtModal');
        if (addCourtModal) {
            const modal = bootstrap.Modal.getInstance(addCourtModal);
            if (modal) {
                modal.hide();
            }
        }
        // Recargar lista
        loadCanchas();
    } catch (err) {
        console.error('Error al crear cancha:', err);
        alert(`❌ Error al crear cancha: ${err.message}`);
    }
}

async function createSchedule() {
    try {
        const scheduleData = {
            court_id: parseInt(document.getElementById('scheduleCourtId').value),
            day: document.getElementById('scheduleDay').value,
            start_time: document.getElementById('scheduleStartTime').value,
            end_time: document.getElementById('scheduleEndTime').value,
            available: document.getElementById('scheduleAvailable').checked
        };
        
        await fetchData('schedules', {
            method: 'POST',
            body: JSON.stringify(scheduleData)
        });
        
        alert('✅ Horario creado correctamente');
        // Limpiar formulario
        document.getElementById('addScheduleForm').reset();
        // Cerrar modal
        bootstrap.Modal.getInstance(document.getElementById('addScheduleModal')).hide();
        // Recargar lista
        loadHorarios();
    } catch (err) {
        alert(`❌ Error al crear horario: ${err.message}`);
    }
}

// ===== FUNCIONES DE NAVEGACIÓN =====

function setupTabNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            
            // Remover clase active de todos los links
            navLinks.forEach(l => l.classList.remove('active'));
            
            // Agregar clase active al link clickeado
            link.classList.add('active');
            
            // Cargar datos según la pestaña
            const target = link.getAttribute('data-bs-target');
            switch(target) {
                case '#dashboard':
                    loadDashboardStats();
                    break;
                case '#usuarios':
                    loadUsuarios();
                    break;
                case '#canchas':
                    loadCanchas();
                    break;
                case '#reservas':
                    loadReservas();
                    break;
                case '#horarios':
                    loadHorarios();
                    break;
                case '#comentarios':
                    loadComentarios();
                    break;
            }
        });
    });
}

// ===== FUNCIONES DE LOGOUT =====

function setupLogoutButtons() {
    const logoutButtons = document.querySelectorAll('#logoutBtn, #logoutBtnNav');
    logoutButtons.forEach(button => {
        button.addEventListener('click', (e) => {
            e.preventDefault();
            logout();
            window.location.href = '/auth/login.html';
        });
    });
}

// ===== INICIALIZACIÓN =====

// ===== INICIALIZACIÓN CON VERIFICACIÓN MEJORADA =====

document.addEventListener('DOMContentLoaded', async () => {
    console.log('Admin panel cargando...');

    // Validar token con el backend antes de continuar
    const token = getAuthToken();
    if (!token) {
        alert('Sesión expirada. Por favor, inicia sesión nuevamente.');
        logout();
        window.location.href = '/auth/login.html';
        return;
    }

    // Validar token en el backend
    try {
        const valid = await validateToken();
        if (!valid) {
            alert('Sesión expirada o inválida. Por favor, inicia sesión nuevamente.');
            logout();
            window.location.href = '/auth/login.html';
            return;
        }
    } catch (e) {
        alert('No se pudo validar la sesión. Por favor, inicia sesión nuevamente.');
        logout();
        window.location.href = '/auth/login.html';
        return;
    }

    // ...resto de la inicialización (usuario, rol, etc)...
    let user = null;
    let attempts = 0;
    const maxAttempts = 5;
    while (!user && attempts < maxAttempts) {
        user = getCurrentUser();
        if (!user) await new Promise(resolve => setTimeout(resolve, 200));
        attempts++;
    }
    if (!user) {
        alert('Sesión no válida. Por favor, inicia sesión nuevamente.');
        logout();
        window.location.href = '/auth/login.html';
        return;
    }
    if (user.role !== 'admin') {
        alert('Acceso denegado. Solo los administradores pueden acceder a esta página.');
        window.location.href = '/auth/login.html';
        return;
    }
    // ...resto de la inicialización...
    const adminNameDisplay = document.getElementById('adminNameDisplay');
    if (adminNameDisplay) adminNameDisplay.textContent = user.name || user.nombre || 'Administrador';
    setupTabNavigation();
    setupLogoutButtons();
    setupFormEventListeners();
    await loadDashboardStats();
    console.log('Admin panel cargado completamente');
});

// Función auxiliar para configurar todos los event listeners
function setupFormEventListeners() {
    const saveCourtBtn = document.getElementById('saveCourtBtn');
    if (saveCourtBtn) {
        saveCourtBtn.addEventListener('click', createCourt);
    }
    
    const saveScheduleBtn = document.getElementById('saveScheduleBtn');
    if (saveScheduleBtn) {
        saveScheduleBtn.addEventListener('click', createSchedule);
    }
    
    const updateUserBtn = document.getElementById('updateUserBtn');
    if (updateUserBtn) {
        updateUserBtn.addEventListener('click', updateUser);
    }
    
    const updateCourtBtn = document.getElementById('updateCourtBtn');
    if (updateCourtBtn) {
        updateCourtBtn.addEventListener('click', updateCourt);
    }
    
    const updateReservationBtn = document.getElementById('updateReservationBtn');
    if (updateReservationBtn) {
        updateReservationBtn.addEventListener('click', updateReservation);
    }
    
    const updateCommentBtn = document.getElementById('updateCommentBtn');
    if (updateCommentBtn) {
        updateCommentBtn.addEventListener('click', updateComment);
    }
    
    // Configurar preview de imágenes
    const courtImages = document.getElementById('courtImages');
    if (courtImages) {
        courtImages.addEventListener('change', function () {
            const file = this.files[0];
            const imagePreview = document.getElementById('imagePreview');
            if (file && imagePreview) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    imagePreview.src = e.target.result;
                    imagePreview.style.display = 'block';
                };
                reader.readAsDataURL(file);
            }
        });
    }
}
}