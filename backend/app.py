import uuid
from flask import Flask, jsonify, render_template, request
from functools import wraps
from flask_cors import CORS
import pymysql
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta
import re
import json
import os
from werkzeug.utils import secure_filename
import traceback
from flask import send_from_directory

# Configuración para subir archivos
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Límite de 16MB
app.config['SECRET_KEY'] = 'tu_clave_secreta_super_segura'  # Cambia esto en producción!
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

# Añadir validación de imagen
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def process_image(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(image_path)
        return f"/uploads/{filename}"
    return None

# Configuración de la base de datos
def conectar():
    try:
        return pymysql.connect(
            host='localhost',
            user='root',
            password='',
            database='flash_reserver',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
    except Exception as e:
        print(f"Error de conexión a MySQL: {str(e)}")
        raise

# Helper para hash de contraseñas
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt, hashed.hex()

# Generar token JWT
def generate_token(user_id):
    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(days=1),
            'iat': datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    except Exception as e:
        return e

# Middleware para rutas protegidas
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token requerido'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['sub']
        except:
            return jsonify({'message': 'Token inválido o expirado'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

##-------------------Autenticación------------------###
##---------------------Registro de Usuario------------------###
@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        nombre = data.get('nombre')
        email = data.get('email')
        password = data.get('password')
        documento = data.get('documento', None)
        rol = data.get('rol', 'usuario')

        # Validaciones
        if not all([nombre, email, password]):
            return jsonify({"success": False, "message": "Todos los campos son requeridos"}), 400
            
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            return jsonify({"success": False, "message": "Email no válido"}), 400
            
        if len(password) < 6:
            return jsonify({"success": False, "message": "La contraseña debe tener al menos 6 caracteres"}), 400

        if rol == 'admin' and not documento:
            return jsonify({"success": False, "message": "Documento requerido para administradores"}), 400

        conn = conectar()
        cursor = conn.cursor()
        
        # Verificar email único
        cursor.execute("SELECT usuario_id FROM Usuarios WHERE email = %s", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "El email ya está registrado"}), 400

        # Hash seguro de la contraseña
        salt, hashed_password = hash_password(password)
        
        # Insertar en BD
        cursor.execute("""
            INSERT INTO Usuarios (nombre, email, password_hash, salt, rol, documento_numero) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (nombre, email, hashed_password, salt, rol, documento))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()

        return jsonify({
            "success": True, 
            "message": "Registro exitoso",
            "userId": user_id
        })
        
    except Exception as ex:
        print(f"Error en registro: {str(ex)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error en el servidor"}), 500
    

##_--------------------Inicio de Sesión------------------###
@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        conn = conectar()
        cursor = conn.cursor()
    
        cursor.execute("""
            SELECT usuario_id, nombre, email, password_hash, salt, rol 
            FROM Usuarios 
            WHERE email = %s
        """, (email,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify({"success": False, "message": "Credenciales incorrectas"}), 401

        # Verificar contraseña
        _, hashed_password = hash_password(password, user['salt'])
        if hashed_password != user['password_hash']:
            return jsonify({"success": False, "message": "Credenciales incorrectas"}), 401
        
        token = generate_token(user['usuario_id'])

        # Asegúrate de que el rol se envía correctamente
        return jsonify({
    "success": True,
    "message": "Inicio de sesión exitoso", 
    "token": token,
    "user": {
        "id": user['usuario_id'],
        "name": user['nombre'],     # opcional, consistente con JS
        "email": user['email'],
        "role": user['rol']         # ← clave estandarizada
    }
})

    except Exception as e:
        print(f"Error en login: {str(e)}")
        return jsonify({"success": False, "message": "Error en el servidor"}), 500

@app.route('/auth/validate-token', methods=['GET'])
@token_required
def validate_token(current_user):
    return jsonify({
        "success": True,
        "message": "Token válido",
        "user_id": current_user
    })

##-------------------Recuperación de Contraseña------------------###
@app.route('/auth/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({"success": False, "message": "Email es requerido"}), 400

        conn = conectar()
        cursor = conn.cursor()
        
        # Verificar si el email existe
        cursor.execute("SELECT usuario_id FROM Usuarios WHERE email = %s", (email,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"success": True, "message": "Si el email existe, te enviaremos un enlace"})
        
        # Generar token de recuperación (simulado)
        reset_token = secrets.token_urlsafe(32)
        reset_link = f"http://localhost:3000/reset-password?token={reset_token}"
        
        # Enviar correo (simulado)
        print(f"Simulando envío de correo a {email} con enlace: {reset_link}")
        
        conn.close()
        return jsonify({
            "success": True,
            "message": "Si el email existe, te enviaremos un enlace para restablecer tu contraseña"
        })
        
    except Exception as e:
        print(f"Error en forgot_password: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error en el servidor"}), 500

@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('newPassword')
        
        if not all([token, new_password]):
            return jsonify({"success": False, "message": "Token y nueva contraseña requeridos"}), 400
            
        if len(new_password) < 6:
            return jsonify({"success": False, "message": "La contraseña debe tener al menos 6 caracteres"}), 400
            
        # En una implementación real, aquí validarías el token
        # Para este ejemplo, asumimos que el token es válido
        
        # Actualizar contraseña
        conn = conectar()
        cursor = conn.cursor()
        
        # Generar nuevo hash de contraseña
        salt, hashed_password = hash_password(new_password)
        
        # En una implementación real, aquí usarías el token para identificar al usuario
        # Para este ejemplo, actualizaremos el primer usuario que encontremos
        cursor.execute("SELECT usuario_id FROM Usuarios LIMIT 1")
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({"success": False, "message": "Usuario no encontrado"}), 404
        
        cursor.execute("""
            UPDATE Usuarios 
            SET password_hash = %s, salt = %s 
            WHERE usuario_id = %s
        """, (hashed_password, salt, user['usuario_id']))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Contraseña actualizada exitosamente"
        })
        
    except Exception as e:
        print(f"Error en reset_password: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error en el servidor"}), 500

##-------------------Gestión de Canchas------------------###
@app.route('/api/courts', methods=['GET'])
@token_required
def get_courts(current_user):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT cancha_id as id, nombre as name, descripcion as description,
               tipo as type, superficie as surface, techada as covered,
               capacidad as capacity, precio_hora as price, 
               imagen_url as image, estado as status
        FROM Canchas
        ORDER BY nombre
    """)
    
    courts = cursor.fetchall()
    conn.close()
    
    return jsonify({
        "success": True,
        "courts": courts
    })

@app.route('/api/courts/<int:court_id>', methods=['GET'])
@token_required
def get_court(current_user, court_id):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT cancha_id as id, nombre as name, descripcion as description,
               tipo as type, superficie as surface, techada as covered,
               capacidad as capacity, precio_hora as price, 
               imagen_url as image, estado as status
        FROM Canchas
        WHERE cancha_id = %s
    """, (court_id,))
    
    court = cursor.fetchone()
    
    if not court:
        conn.close()
        return jsonify({"success": False, "message": "Cancha no encontrada"}), 404
    
    conn.close()
    return jsonify({"success": True, "court": court})

##-------------------Gestión de Canchas------------------###
@app.route('/api/courts', methods=['POST'])
@token_required
def create_court(current_user):
    try:
        # Verificar si el usuario es administrador
        conn = conectar()
        cursor = conn.cursor()
        cursor.execute("SELECT rol FROM Usuarios WHERE usuario_id = %s", (current_user,))
        user = cursor.fetchone()
        
        if user['rol'] != 'admin':
            conn.close()
            return jsonify({"success": False, "message": "No autorizado"}), 403

        # Obtener datos del formulario
        data = request.form
        
        # Validar campos requeridos
        required_fields = ['nombre', 'tipo', 'superficie', 'capacidad', 'precio_hora']
        if not all(field in data for field in required_fields):
            conn.close()
            return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400

        # Procesar datos
        nombre = data['nombre']
        descripcion = data.get('descripcion', '')
        tipo = data['tipo']
        superficie = data['superficie']
        techada = 1 if 'techada' in data else 0
        capacidad = int(data['capacidad'])
        precio_hora = float(data['precio_hora'])
        estado = 'disponible'  # Estado por defecto

        # Procesar imagen
        image_url = None
        if 'imagen' in request.files:
            image_file = request.files['imagen']
            if image_file.filename != '' and allowed_file(image_file.filename):
                filename = secure_filename(f"{uuid.uuid4().hex}_{image_file.filename}")
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                image_url = f"/uploads/{filename}"

        # Insertar en la base de datos
        cursor.execute("""
            INSERT INTO Canchas (
                nombre, descripcion, tipo, superficie, techada, 
                capacidad, precio_hora, imagen_url, estado, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
        """, (nombre, descripcion, tipo, superficie, techada, capacidad, precio_hora, image_url, estado))
        
        conn.commit()
        court_id = cursor.lastrowid
        
        # Crear horarios por defecto (8am-10pm para cada día)
        days = ['lunes', 'martes', 'miércoles', 'jueves', 'viernes', 'sábado', 'domingo']
        for day in days:
            cursor.execute("""
                INSERT INTO Horarios (cancha_id, dia_semana, hora_inicio, hora_fin, disponible)
                VALUES (%s, %s, '08:00:00', '22:00:00', 1)
            """, (court_id, day))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Cancha creada exitosamente",
            "courtId": court_id
        }), 201
        
    except Exception as e:
        print(f"Error al crear cancha: {str(e)}")
        traceback.print_exc()
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al crear cancha"}), 500
    
    


@app.route('/api/courts/<int:court_id>', methods=['PUT'])
@token_required
def update_court(current_user, court_id):
    try:
        # Verificar si el usuario es administrador
        conn = conectar()
        cursor = conn.cursor()
        cursor.execute("SELECT rol FROM Usuarios WHERE usuario_id = %s", (current_user,))
        user = cursor.fetchone()
        
        if user['rol'] != 'admin':
            conn.close()
            return jsonify({"success": False, "message": "No autorizado"}), 403

        data = request.form
        
        # Validar campos requeridos
        required_fields = ['nombre', 'tipo', 'superficie', 'capacidad', 'precio_hora']
        if not all(field in data for field in required_fields):
            conn.close()
            return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400

        # Procesar datos
        nombre = data['nombre']
        descripcion = data.get('descripcion', '')
        tipo = data['tipo']
        superficie = data['superficie']
        techada = 1 if 'techada' in data else 0
        capacidad = int(data['capacidad'])
        precio_hora = float(data['precio_hora'])
        estado = data.get('estado', 'disponible')

        # Procesar imagen
        image_url = None
        if 'imagen' in request.files:
            image_file = request.files['imagen']
            if image_file.filename != '' and allowed_file(image_file.filename):
                filename = secure_filename(f"{uuid.uuid4().hex}_{image_file.filename}")
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                image_url = f"/uploads/{filename}"

        # Verificar si la cancha existe
        cursor.execute("SELECT 1 FROM Canchas WHERE cancha_id = %s", (court_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Cancha no encontrada"}), 404
        
        # Actualizar cancha
        if image_url:
            cursor.execute("""
                UPDATE Canchas SET
                    nombre = %s,
                    descripcion = %s,
                    tipo = %s,
                    superficie = %s,
                    techada = %s,
                    capacidad = %s,
                    precio_hora = %s,
                    imagen_url = %s,
                    estado = %s,
                    updated_at = NOW()
                WHERE cancha_id = %s
            """, (nombre, descripcion, tipo, superficie, techada, capacidad, precio_hora, image_url, estado, court_id))
        else:
            cursor.execute("""
                UPDATE Canchas SET
                    nombre = %s,
                    descripcion = %s,
                    tipo = %s,
                    superficie = %s,
                    techada = %s,
                    capacidad = %s,
                    precio_hora = %s,
                    estado = %s,
                    updated_at = NOW()
                WHERE cancha_id = %s
            """, (nombre, descripcion, tipo, superficie, techada, capacidad, precio_hora, estado, court_id))
        
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        
        if affected == 0:
            return jsonify({"success": False, "message": "No se pudo actualizar la cancha"}), 400
        
        return jsonify({
            "success": True,
            "message": "Cancha actualizada exitosamente"
        })
        
    except Exception as e:
        print(f"Error al actualizar cancha: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al actualizar cancha"}), 500

@app.route('/api/courts/<int:court_id>/delete', methods=['DELETE'])
@token_required
def delete_court(current_user, court_id):
    try:
        conn = conectar()
        cursor = conn.cursor()

        # Verificar si la cancha existe
        cursor.execute("SELECT * FROM Canchas WHERE cancha_id = %s", (court_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Cancha no encontrada"}), 404

        # Eliminación lógica: marcar como inactiva
        cursor.execute("""
            UPDATE Canchas SET estado = 'inactiva' WHERE cancha_id = %s
        """, (court_id,))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Cancha eliminada (inactivada)"})
    except Exception as e:
        print(f"Error al eliminar cancha: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al eliminar la cancha"}), 500

##-------------------Gestión de Horarios------------------###
@app.route('/api/courts/<int:court_id>/schedules', methods=['GET'])
@token_required
def get_court_schedules(current_user, court_id):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT horario_id as id, dia_semana as day, 
               TIME_FORMAT(hora_inicio, '%%H:%%i') as start_time,
               TIME_FORMAT(hora_fin, '%%H:%%i') as end_time,
               disponible as available
        FROM Horarios
        WHERE cancha_id = %s
        ORDER BY FIELD(dia_semana, 'lunes', 'martes', 'miércoles', 'jueves', 'viernes', 'sábado', 'domingo'),
                 hora_inicio
    """, (court_id,))
    
    schedules = cursor.fetchall()
    conn.close()
    
    return jsonify({
        "success": True,
        "schedules": schedules
    })

@app.route('/api/schedules/<int:schedule_id>', methods=['PUT'])
@token_required
def update_schedule(current_user, schedule_id):
    try:
        data = request.get_json()
        
        required_fields = ['start_time', 'end_time', 'available']
        if not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
        
        start_time = data['start_time']
        end_time = data['end_time']
        available = data['available']
        
        conn = conectar()
        cursor = conn.cursor()
        
        # Verificar si el horario existe
        cursor.execute("SELECT 1 FROM Horarios WHERE horario_id = %s", (schedule_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Horario no encontrado"}), 404
        
        # Actualizar horario
        cursor.execute("""
            UPDATE Horarios SET
                hora_inicio = %s,
                hora_fin = %s,
                disponible = %s
            WHERE horario_id = %s
        """, (start_time, end_time, available, schedule_id))
        
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        
        if affected == 0:
            return jsonify({"success": False, "message": "No se pudo actualizar el horario"}), 400
        
        return jsonify({
            "success": True,
            "message": "Horario actualizado exitosamente"
        })
        
    except Exception as e:
        print(f"Error al actualizar horario: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al actualizar horario"}), 500

##-------------------Gestión de Reservas------------------###
@app.route('/api/reservations', methods=['GET'])
@token_required
def get_reservations(current_user):
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    date_from = request.args.get('dateFrom')
    date_to = request.args.get('dateTo')
    court_id = request.args.get('courtId')
    status = request.args.get('status')
    
    conn = conectar()
    cursor = conn.cursor()
    
    # Construir consulta base
    query = """
        SELECT R.reserva_id as id, R.fecha_reserva as date, 
               TIME_FORMAT(R.hora_inicio, '%%H:%%i') as time,
               TIME_FORMAT(R.hora_fin, '%%H:%%i') as end_time,
               R.estado as status, R.codigo_reserva as code,
               C.nombre as court_name, C.cancha_id as court_id,
               U.nombre as user_name, U.usuario_id as user_id,
               TIMESTAMPDIFF(HOUR, R.hora_inicio, R.hora_fin) as duration
        FROM Reservas R
        JOIN Canchas C ON R.cancha_id = C.cancha_id
        JOIN Usuarios U ON R.usuario_id = U.usuario_id
        JOIN Horarios H ON R.horario_id = H.horario_id
    """
    
    conditions = []
    params = []
    
    # Aplicar filtros
    if date_from:
        conditions.append("R.fecha_reserva >= %s")
        params.append(date_from)
    if date_to:
        conditions.append("R.fecha_reserva <= %s")
        params.append(date_to)
    if court_id:
        conditions.append("R.cancha_id = %s")
        params.append(court_id)
    if status:
        conditions.append("R.estado = %s")
        params.append(status)
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    # Contar total para paginación
    count_query = "SELECT COUNT(*) as total FROM (" + query + ") as subquery"
    cursor.execute(count_query, params)
    total = cursor.fetchone()['total']
    
    # Añadir orden y límite para paginación
    query += " ORDER BY R.fecha_reserva DESC, R.hora_inicio DESC LIMIT %s OFFSET %s"
    params.extend([per_page, offset])
    
    cursor.execute(query, params)
    reservations = cursor.fetchall()
    
    # Obtener lista de canchas para filtro
    cursor.execute("SELECT cancha_id as id, nombre as name FROM Canchas")
    courts = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        "success": True,
        "reservations": reservations,
        "total": total,
        "courts": courts
    })

@app.route('/api/reservations/<int:reservation_id>', methods=['GET'])
@token_required
def get_reservation(current_user, reservation_id):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT R.reserva_id as id, R.fecha_reserva as date, 
               TIME_FORMAT(R.hora_inicio, '%%H:%%i') as time,
               TIME_FORMAT(R.hora_fin, '%%H:%%i') as end_time,
               R.estado as status, R.codigo_reserva as code,
               C.nombre as court_name, C.cancha_id as court_id,
               U.nombre as user_name, U.usuario_id as user_id, U.email as user_email,
               TIMESTAMPDIFF(HOUR, R.hora_inicio, R.hora_fin) as duration,
               H.horario_id as schedule_id,
               DATE_FORMAT(R.created_at, '%%d/%%m/%%Y %%H:%%i') as created_at,
               DATE_FORMAT(R.updated_at, '%%d/%%m/%%Y %%H:%%i') as updated_at
        FROM Reservas R
        JOIN Canchas C ON R.cancha_id = C.cancha_id
        JOIN Usuarios U ON R.usuario_id = U.usuario_id
        JOIN Horarios H ON R.horario_id = H.horario_id
        WHERE R.reserva_id = %s
    """, (reservation_id,))
    
    reservation = cursor.fetchone()
    
    if not reservation:
        conn.close()
        return jsonify({"success": False, "message": "Reserva no encontrada"}), 404
    
    conn.close()
    return jsonify({"success": True, "reservation": reservation})

@app.route('/api/reservations', methods=['POST'])
@token_required
def create_reservation(current_user):
    try:
        data = request.get_json()
        
        required_fields = ['court_id', 'user_id', 'date', 'schedule_id']
        if not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
        
        court_id = int(data['court_id'])
        user_id = int(data['user_id'])
        date = data['date']
        schedule_id = int(data['schedule_id'])
        status = data.get('status', 'confirmada')
        
        conn = conectar()
        cursor = conn.cursor()
        
        # Obtener información del horario
        cursor.execute("""
            SELECT hora_inicio, hora_fin FROM Horarios 
            WHERE horario_id = %s AND cancha_id = %s
        """, (schedule_id, court_id))
        schedule = cursor.fetchone()
        
        if not schedule:
            conn.close()
            return jsonify({"success": False, "message": "Horario no válido para esta cancha"}), 400
        
        start_time = schedule['hora_inicio']
        end_time = schedule['hora_fin']
        
        # Verificar disponibilidad
        cursor.execute("""
            SELECT 1 FROM Reservas 
            WHERE cancha_id = %s AND fecha_reserva = %s AND horario_id = %s
            AND estado IN ('pendiente', 'confirmada')
        """, (court_id, date, schedule_id))
        
        if cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "La cancha no está disponible en ese horario"}), 400
        
        # Generar código de reserva único
        code = secrets.token_hex(3).upper()
        
        # Crear reserva
        cursor.execute("""
            INSERT INTO Reservas (
                usuario_id, cancha_id, horario_id, fecha_reserva, 
                hora_inicio, hora_fin, estado, codigo_reserva
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, court_id, schedule_id, date, start_time, end_time, status, code))
        
        conn.commit()
        reservation_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Reserva creada exitosamente",
            "reservationId": reservation_id,
            "reservationCode": code
        })
        
    except Exception as e:
        print(f"Error al crear reserva: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al crear reserva"}), 500

@app.route('/api/reservations/<int:reservation_id>/confirm', methods=['PUT'])
@token_required
def confirm_reservation(current_user, reservation_id):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE Reservas 
        SET estado = 'confirmada' 
        WHERE reserva_id = %s AND estado = 'pendiente'
    """, (reservation_id,))
    
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    
    if affected == 0:
        return jsonify({"success": False, "message": "Reserva no encontrada o ya confirmada"}), 404
    
    return jsonify({"success": True, "message": "Reserva confirmada"})

@app.route('/api/reservations/<int:reservation_id>/cancel', methods=['PUT'])
@token_required
def cancel_reservation(current_user, reservation_id):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE Reservas 
        SET estado = 'cancelada' 
        WHERE reserva_id = %s AND estado IN ('pendiente', 'confirmada')
    """, (reservation_id,))
    
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    
    if affected == 0:
        return jsonify({"success": False, "message": "Reserva no encontrada o ya cancelada"}), 404
    
    return jsonify({"success": True, "message": "Reserva cancelada"})

##-------------------Gestión de Usuarios------------------###
@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    name_filter = request.args.get('name')
    email_filter = request.args.get('email')
    
    conn = conectar()
    cursor = conn.cursor()
    
    # Construir consulta base
    query = """
        SELECT usuario_id as id, nombre as name, email, 
               documento_numero as document, rol as role,
               CASE 
                   WHEN rol = 'admin' THEN 'Administrador'
                   ELSE 'Usuario'
               END as role_text,
               DATE_FORMAT(created_at, '%%d/%%m/%%Y') as registration_date,
               (SELECT COUNT(*) FROM Reservas WHERE usuario_id = Usuarios.usuario_id) as reservations_count
        FROM Usuarios
    """
    
    conditions = []
    params = []
    
    # Aplicar filtros
    if name_filter:
        conditions.append("nombre LIKE %s")
        params.append(f"%{name_filter}%")
    if email_filter:
        conditions.append("email LIKE %s")
        params.append(f"%{email_filter}%")
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    # Contar total para paginación
    count_query = "SELECT COUNT(*) as total FROM (" + query + ") as subquery"
    cursor.execute(count_query, params)
    total = cursor.fetchone()['total']
    
    # Añadir orden y límite para paginación
    query += " ORDER BY nombre ASC LIMIT %s OFFSET %s"
    params.extend([per_page, offset])
    
    cursor.execute(query, params)
    users = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        "success": True,
        "users": users,
        "total": total
    })

@app.route('/api/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT usuario_id as id, nombre as name, email, 
               documento_numero as document, rol as role,
               DATE_FORMAT(created_at, '%%d/%%m/%%Y') as registration_date,
               (SELECT COUNT(*) FROM Reservas WHERE usuario_id = %s) as reservations_count
        FROM Usuarios
        WHERE usuario_id = %s
    """, (user_id, user_id))
    
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({"success": False, "message": "Usuario no encontrado"}), 404
    
    conn.close()
    return jsonify({"success": True, "user": user})

##-------------------Estadísticas------------------###
@app.route('/api/stats/daily-reservations', methods=['GET'])
@token_required
def daily_reservations_stats(current_user):
    conn = conectar()
    cursor = conn.cursor()
    
    # Reservas por día de la semana (últimos 7 días)
    cursor.execute("""
        SELECT DAYNAME(fecha_reserva) as day, COUNT(*) as count
        FROM Reservas
        WHERE fecha_reserva BETWEEN DATE_SUB(CURDATE(), INTERVAL 7 DAY) AND CURDATE()
        GROUP BY DAYNAME(fecha_reserva)
        ORDER BY fecha_reserva
    """)
    
    daily_data = cursor.fetchall()
    
    # Días de la semana en español
    days_map = {
        'Monday': 'Lunes',
        'Tuesday': 'Martes',
        'Wednesday': 'Miércoles',
        'Thursday': 'Jueves',
        'Friday': 'Viernes',
        'Saturday': 'Sábado',
        'Sunday': 'Domingo'
    }
    
    # Formatear datos para el gráfico
    days = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo']
    counts = [0] * 7
    
    for row in daily_data:
        day_name = days_map.get(row['day'], row['day'])
        if day_name in days:
            index = days.index(day_name)
            counts[index] = row['count']
    
    conn.close()
    return jsonify({
        "success": True,
        "labels": days,
        "data": counts
    })

@app.route('/api/stats/court-reservations', methods=['GET'])
@token_required
def court_reservations_stats(current_user):
    conn = conectar()
    cursor = conn.cursor()
    
    # Reservas por cancha (este mes)
    cursor.execute("""
        SELECT C.nombre as court_name, COUNT(*) as count
        FROM Reservas R
        JOIN Canchas C ON R.cancha_id = C.cancha_id
        WHERE MONTH(R.fecha_reserva) = MONTH(CURDATE())
        AND YEAR(R.fecha_reserva) = YEAR(CURDATE())
        GROUP BY C.nombre
        ORDER BY count DESC
    """)
    
    court_data = cursor.fetchall()
    
    # Formatear datos para el gráfico
    labels = [row['court_name'] for row in court_data]
    data = [row['count'] for row in court_data]
    
    conn.close()
    return jsonify({
        "success": True,
        "labels": labels,
        "data": data
    })

##-------------------Dashboard------------------###
@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def dashboard_stats(current_user):
    conn = conectar()
    cursor = conn.cursor()
    
    # Reservas de hoy
    cursor.execute("""
        SELECT COUNT(*) as count FROM Reservas 
        WHERE fecha_reserva = CURDATE() AND estado IN ('pendiente', 'confirmada')
    """)
    today_reservations = cursor.fetchone()['count']
    
    # Canchas activas
    cursor.execute("SELECT COUNT(*) as count FROM Canchas WHERE estado = 'disponible'")
    active_courts = cursor.fetchone()['count']
    
    # Usuarios registrados
    cursor.execute("SELECT COUNT(*) as count FROM Usuarios")
    total_users = cursor.fetchone()['count']
    
    conn.close()
    
    return jsonify({
        "success": True,
        "todayReservations": today_reservations,
        "activeCourts": active_courts,
        "totalUsers": total_users
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)