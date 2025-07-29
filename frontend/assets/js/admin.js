import { getAuthToken, getCurrentUser, logout, isAdmin } from './auth.js';

const API_URL = 'http://localhost:5000';

// Configurar eventos de logout
function setupLogoutButtons() {
    const logoutButtons = [
        document.getElementById('logoutBtn'),
        document.getElementById('logoutBtnNav')
    ];
    
    logoutButtons.forEach(button => {
        if (button) {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                logout();
                window.location.href = '/auth/login.html';
            });
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const user = getCurrentUser();
    if (!user || user.rol !== 'admin') {
        alert('Acceso denegado');
        window.location.href = '/auth/login.html';
        return;
    }

    document.getElementById('adminNameDisplay').textContent = user.nombre;

    // Configurar botones de logout
    setupLogoutButtons();

    loadDashboardStats();
    loadUsuarios();
    loadCanchas();
    loadReservas();

    // Evento actualizar cancha
    document.getElementById('updateCourtBtn').addEventListener('click', updateCourt);
});

async function fetchData(endpoint) {
    const res = await fetch(`${API_URL}/api/${endpoint}`, {
        headers: {
            'Authorization': `Bearer ${getAuthToken()}`
        }
    });

    if (!res.ok) throw new Error(`Error al cargar ${endpoint}`);
    return await res.json();
}

async function loadDashboardStats() {
    try {
        const data = await fetchData('dashboard/stats');
        document.getElementById('todayReservations').textContent = data.todayReservations;
        document.getElementById('activeCourts').textContent = data.activeCourts;
        document.getElementById('totalUsers').textContent = data.totalUsers;
    } catch (err) {
        console.error(err.message);
    }
}

async function loadUsuarios() {
    try {
        const response = await fetchData('users');
        const tbody = document.querySelector('#usersTable tbody');
        tbody.innerHTML = '';
        response.users.forEach(u => {
            tbody.innerHTML += `
                <tr>
                    <td>${u.id}</td>
                    <td>${u.name}</td>
                    <td>${u.email}</td>
                    <td>${u.document || '-'}</td>
                    <td>${u.reservations_count || 0}</td>
                    <td>${u.registration_date || '-'}</td>
                    <td>${u.status_text || 'Activo'}</td>
                    <td><button class="btn btn-sm btn-danger">Eliminar</button></td>
                </tr>`;
        });
    } catch (err) {
        console.error(err.message);
    }
}

async function loadCanchas() {
    try {
        const response = await fetchData('courts');
        const tbody = document.querySelector('#courtsTable tbody');
        tbody.innerHTML = '';
        response.courts.forEach(c => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${c.id}</td>
                <td>${c.name}</td>
                <td>${c.type || '-'}</td>
                <td>${c.surface || '-'}</td>
                <td>${c.covered ? 'Sí' : 'No'}</td>
                <td>${c.status_text}</td>
                <td>
                    <button class="btn btn-sm btn-warning btn-edit-court" data-id="${c.id}">Editar</button>
                    <button class="btn btn-sm btn-danger btn-delete-court" data-id="${c.id}">Eliminar</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    } catch (err) {
        console.error(err.message);
    }
}

async function loadReservas() {
    try {
        const response = await fetchData('reservations/recent');
        const tbody = document.querySelector('#reservationsTable tbody');
        tbody.innerHTML = '';
        response.reservations.forEach(r => {
            tbody.innerHTML += `
                <tr>
                    <td>${r.id}</td>
                    <td>${r.court_name}</td>
                    <td>${r.user_name}</td>
                    <td>${r.date} ${r.time}</td>
                    <td>${r.duration || '1h'}</td>
                    <td>${r.status}</td>
                    <td><button class="btn btn-sm btn-info">Ver</button></td>
                </tr>`;
        });
    } catch (err) {
        console.error(err.message);
    }
}

// Evento delegado para abrir modal de edición
document.addEventListener('click', async (e) => {
    if (e.target.classList.contains('btn-edit-court')) {
        const id = e.target.dataset.id;
        try {
            const res = await fetch(`${API_URL}/api/courts/${id}`, {
                headers: { 'Authorization': `Bearer ${getAuthToken()}` }
            });
            const data = await res.json();
            if (!data.success) throw new Error(data.message);
            const c = data.court;

            document.getElementById('editCourtId').value = c.id;
            document.getElementById('editCourtName').value = c.name;
            document.getElementById('editCourtDescription').value = c.description;
            document.getElementById('editCourtStatus').value = c.status;
            document.getElementById('editCourtPrice').value = c.price;

            // Mostrar modal
            const modal = new bootstrap.Modal(document.getElementById('editCourtModal'));
            modal.show();

        } catch (err) {
            console.error(err);
            alert('Error al cargar datos de la cancha');
        }
    }

    if (e.target.classList.contains('btn-delete-court')) {
        const id = e.target.dataset.id;
        if (!confirm('¿Seguro que deseas eliminar esta cancha?')) return;

        try {
            const res = await fetch(`${API_URL}/api/courts/${id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${getAuthToken()}` }
            });
            const data = await res.json();
            if (!data.success) throw new Error(data.message);
            alert('Cancha eliminada');
            loadCanchas();
        } catch (err) {
            console.error(err);
            alert('Error al eliminar cancha');
        }
    }
});

// PUT: actualizar cancha
async function updateCourt() {
    const id = document.getElementById('editCourtId').value;
    const formData = new FormData();
    formData.append('nombre', document.getElementById('editCourtName').value);
    formData.append('descripcion', document.getElementById('editCourtDescription').value);
    formData.append('precio', document.getElementById('editCourtPrice').value);
    formData.append('status', document.getElementById('editCourtStatus').value);
    const image = document.getElementById('editCourtImages').files[0];
    if (image) formData.append('imagen', image);

    try {
        const res = await fetch(`${API_URL}/api/courts/${id}`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${getAuthToken()}` },
            body: formData
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.message);

        alert('Cancha actualizada');
        const modal = bootstrap.Modal.getInstance(document.getElementById('editCourtModal'));
        modal.hide();
        loadCanchas();
    } catch (err) {
        console.error(err);
        alert('Error al actualizar cancha');
    }
}

document.getElementById('saveCourtBtn').addEventListener('click', async () => {
    try {
        // Validar campos obligatorios
        const name = document.getElementById('courtName').value;
        const description = document.getElementById('courtDescription').value;
        const price = document.getElementById('courtPrice').value;

        if (!name || !description || !price) {
            alert("❌ Nombre, descripción y precio son obligatorios");
            return;
        }

        // Preparar datos para enviar
        const formData = new FormData();
        formData.append('nombre', document.getElementById('courtName').value);
        formData.append('tipo', document.getElementById('courtType').value);
        formData.append('superficie', document.getElementById('courtSurface').value);
        formData.append('capacidad', document.getElementById('courtCapacity').value);
        formData.append('precio_hora', document.getElementById('courtPrice').value);
        formData.append('descripcion', document.getElementById('courtDescription').value);

        // Checkbox
        if (document.getElementById('coveredCourt').checked) {
            formData.append('techada', '1');
        }

        // Imagen
        const imageFile = document.getElementById('courtImages').files[0];
        if (imageFile) {
            formData.append('imagen', imageFile);
        }

        // Enviar al servidor
        const res = await fetch(`${API_URL}/api/courts`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${getAuthToken()}` },
            body: formData
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.message || "Error del servidor");

        alert("✅ Cancha creada exitosamente");
        // Cerrar modal y recargar lista
        bootstrap.Modal.getInstance(document.getElementById('addCourtModal')).hide();
        loadCanchas();
    } catch (err) {
        console.error("Error:", err);
        alert(`❌ ${err.message || "Error al crear cancha"}`);
    }
});

document.getElementById('courtImages').addEventListener('change', function () {
    const previewContainer = document.getElementById('addImagesPreview');
    previewContainer.innerHTML = ''; // limpiar previa

    const files = this.files;
    if (!files || files.length === 0) return;

    Array.from(files).forEach(file => {
        if (!file.type.startsWith('image/')) return;

        const reader = new FileReader();
        reader.onload = function (e) {
            const img = document.createElement('img');
            img.src = e.target.result;
            img.alt = 'Vista previa';
            img.style.width = '100px';
            img.style.height = '100px';
            img.style.objectFit = 'cover';
            img.classList.add('rounded', 'shadow');
            previewContainer.appendChild(img);
        };
        reader.readAsDataURL(file);
    });
});