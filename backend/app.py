from flask import Flask, jsonify, render_template, request
from functools import wraps
from flask_cors import CORS
import pymysql
import hashlib
import secrets
import psycopg2
import re
import jwt
from datetime import datetime, timedelta
from datetime import time
import json
import random
import string
from flask import Flask, send_from_directory
import os
import pymysql.cursors
from werkzeug.utils import secure_filename

# Configuración para subir archivos
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'tu_clave_secreta_super_segura'  # Cambia esto en producción!
# Crear directorio de uploads si no existe
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Configuración de la base de datos (mejorado)
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

# Helper para hash de contraseñas (mejorado)
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
        return jwt.encode(
            payload,
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
    except Exception as e:
        return e

# Verificar token JWT
def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Token expirado. Por favor inicia sesión nuevamente.'
    except jwt.InvalidTokenError:
        return 'Token inválido. Por favor inicia sesión nuevamente.'

# Middleware para rutas protegidas
def token_required(f):
    @wraps(f)  # ✅ ESTO ES LO QUE SOLUCIONA EL ERROR
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


##-------------------Registro------------------###
@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        nombre = data.get('nombre')
        email = data.get('email')
        password = data.get('password')

        # Validaciones mejoradas
        if not all([nombre, email, password]):
            return jsonify({"success": False, "message": "Todos los campos son requeridos"}), 400
            
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            return jsonify({"success": False, "message": "Email no válido"}), 400
            
        if len(password) < 6:
            return jsonify({"success": False, "message": "La contraseña debe tener al menos 6 caracteres"}), 400

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
            INSERT INTO Usuarios (nombre, email, password_hash, salt, rol) 
            VALUES (%s, %s, %s, %s, 'usuario')
        """, (nombre, email, hashed_password, salt))
        
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

##-------------------Login------------------###
@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')  # Texto plano desde frontend

        conn = conectar()
        cursor = conn.cursor()
    
        # Buscar usuario
        cursor.execute("""
            SELECT usuario_id, nombre, email, password_hash, salt, rol 
            FROM Usuarios 
            WHERE email = %s
        """, (email,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify({"success": False, "message": "Contraseña o email incorrectos"}), 401

        # Verificar contraseña (hash seguro)
        _, hashed_password = hash_password(password, user['salt'])
        if hashed_password != user['password_hash']:
            return jsonify({"success": False, "message": "Contraseña o email incorrectos"}), 401

        return jsonify({
            "success": True,
            "message": "Inicio de sesión exitoso", 
            "user": {
                "id": user['usuario_id'],
                "name": user['nombre'],
                "email": user['email'],
                "role": user['rol']
            }
        })

    except Exception as e:
        print(f"Error en login: {str(e)}")
        return jsonify({"success": False, "message": "Error en el servidor"}), 500

###------------------Validación de token------------------###
@app.route('/auth/validate-token', methods=['GET'])
@token_required
def validate_token(current_user):
    return jsonify({
        "success": True,
        "message": "Token válido",
        "user_id": current_user
    })
    
# -------------------- Recuperación de Contraseña --------------------
# Generar token de recuperación
def generate_reset_token(email):
    payload = {
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow(),
        'sub': email,
        'purpose': 'password_reset'
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Enviar correo de recuperación (simulado)
def send_reset_email(email, reset_link):
    print(f"Simulando envío de correo a {email} con enlace: {reset_link}")
    return True

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
            return jsonify({"success": True, "message": "Si el email existe, te enviaremos un enlace"})  # No revelar si el email existe o no

        # Generar token de recuperación
        reset_token = generate_reset_token(email)
        reset_link = f"http://localhost:3000/frontend/auth/reset-password.html?token={reset_token}"
        
        # Enviar correo (en producción usarías un servicio real como SendGrid)
        send_reset_email(email, reset_link)
        
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

@app.route('/auth/validate-reset-token', methods=['POST'])
def validate_reset_token():
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({"success": False, "message": "Token requerido"}), 400
            
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if payload.get('purpose') != 'password_reset':
                return jsonify({"success": False, "message": "Token inválido"}), 400
                
            return jsonify({
                "success": True,
                "message": "Token válido",
                "email": payload['sub']
            })
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "El enlace ha expirado"}), 400
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Token inválido"}), 400
            
    except Exception as e:
        print(f"Error en validate_reset_token: {str(e)}")
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
            
        # Validar token
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if payload.get('purpose') != 'password_reset':
                return jsonify({"success": False, "message": "Token inválido"}), 400
                
            email = payload['sub']
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "El enlace ha expirado"}), 400
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Token inválido"}), 400
            
        # Actualizar contraseña
        conn = conectar()
        cursor = conn.cursor()
        
        # Generar nuevo hash de contraseña
        salt, hashed_password = hash_password(new_password)
        
        cursor.execute("""
            UPDATE Usuarios 
            SET password_hash = %s, salt = %s 
            WHERE email = %s
        """, (hashed_password, salt, email))
        
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
    
  ##-------------------Endpoints para el Dashboard------------------###
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

@app.route('/api/reservations/recent', methods=['GET'])
@token_required
def recent_reservations(current_user):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT R.reserva_id as id, R.fecha_reserva as date, R.hora_inicio as time, 
               R.estado as status, R.hora_fin as end_time,
               C.nombre as court_name, U.nombre as user_name
        FROM Reservas R
        JOIN Canchas C ON R.cancha_id = C.cancha_id
        JOIN Usuarios U ON R.usuario_id = U.usuario_id
        ORDER BY R.fecha_reserva DESC, R.hora_inicio DESC
        LIMIT 10
    """)
    
    reservations = cursor.fetchall()
    conn.close()
    
    return jsonify({
        "success": True,
        "reservations": reservations
    })
    
##------------------Endpoints para Gestión de Reservas------------------###
@app.route('/api/reservations', methods=['GET'])
@token_required
def get_reservations(current_user):
    # Obtener parámetros de filtrado
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
        SELECT R.reserva_id as id, R.fecha_reserva as date, R.hora_inicio as time, 
               R.estado as status, R.hora_fin as end_time,
               C.nombre as court_name, C.cancha_id as court_id,
               U.nombre as user_name, U.usuario_id as user_id,
               TIMESTAMPDIFF(HOUR, R.hora_inicio, R.hora_fin) as duration
        FROM Reservas R
        JOIN Canchas C ON R.cancha_id = C.cancha_id
        JOIN Usuarios U ON R.usuario_id = U.usuario_id
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
        SELECT R.reserva_id as id, R.fecha_reserva as date, R.hora_inicio as time, 
               R.estado as status, R.hora_fin as end_time, R.codigo_reserva as code,
               C.nombre as court_name, C.cancha_id as court_id,
               U.nombre as user_name, U.usuario_id as user_id, U.email as user_email,
               TIMESTAMPDIFF(HOUR, R.hora_inicio, R.hora_fin) as duration,
               R.created_at as created_at, R.updated_at as updated_at
        FROM Reservas R
        JOIN Canchas C ON R.cancha_id = C.cancha_id
        JOIN Usuarios U ON R.usuario_id = U.usuario_id
        WHERE R.reserva_id = %s
    """, (reservation_id,))
    
    reservation = cursor.fetchone()
    
    if not reservation:
        conn.close()
        return jsonify({"success": False, "message": "Reserva no encontrada"}), 404
    
    conn.close()
    return jsonify({"success": True, "reservation": reservation})

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

@app.route('/api/reservations/form-data', methods=['GET'])
@token_required
def get_reservation_form_data(current_user):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("SELECT cancha_id as id, nombre as name FROM Canchas WHERE estado = 'disponible'")
    courts = cursor.fetchall()
    
    cursor.execute("SELECT usuario_id as id, nombre as name FROM Usuarios")
    users = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        "success": True,
        "courts": courts,
        "users": users
    })

@app.route('/api/reservations', methods=['POST'])
@token_required
def create_reservation(current_user):
    data = request.get_json()
    
    required_fields = ['courtId', 'userId', 'date', 'time', 'duration', 'status']
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
    
    try:
        court_id = int(data['courtId'])
        user_id = int(data['userId'])
        date = data['date']
        time = data['time']
        duration = float(data['duration'])
        status = data['status']
        
        start_time = datetime.strptime(time, '%H:%M').time()
        end_time = (datetime.combine(datetime.today(), start_time) + timedelta(hours=duration)).time()
        
        conn = conectar()
        cursor = conn.cursor()
        
        # Verificar disponibilidad
        cursor.execute("""
            SELECT 1 FROM Reservas 
            WHERE cancha_id = %s AND fecha_reserva = %s 
            AND (
                (hora_inicio < %s AND hora_fin > %s) OR
                (hora_inicio >= %s AND hora_inicio < %s) OR
                (hora_fin > %s AND hora_fin <= %s)
            )
            AND estado IN ('pendiente', 'confirmada')
        """, (court_id, date, end_time, start_time, start_time, end_time, start_time, end_time))
        
        if cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "La cancha no está disponible en ese horario"}), 400
        
        # Crear reserva
        cursor.execute("""
            INSERT INTO Reservas (
                usuario_id, cancha_id, fecha_reserva, hora_inicio, hora_fin, estado
            ) VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, court_id, date, start_time, end_time, status))
        
        conn.commit()
        reservation_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Reserva creada exitosamente",
            "reservationId": reservation_id
        })
        
    except Exception as e:
        print(f"Error al crear reserva: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al crear reserva"}), 500

@app.route('/api/reservations/<int:reservation_id>', methods=['PUT'])
@token_required
def update_reservation(current_user, reservation_id):
    data = request.get_json()
    
    required_fields = ['courtId', 'userId', 'date', 'time', 'duration', 'status']
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
    
    try:
        court_id = int(data['courtId'])
        user_id = int(data['userId'])
        date = data['date']
        time = data['time']
        duration = float(data['duration'])
        status = data['status']
        
        start_time = datetime.strptime(time, '%H:%M').time()
        end_time = (datetime.combine(datetime.today(), start_time) + timedelta(hours=duration)).time()
        
        conn = conectar()
        cursor = conn.cursor()
        
        # Verificar si la reserva existe
        cursor.execute("SELECT 1 FROM Reservas WHERE reserva_id = %s", (reservation_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Reserva no encontrada"}), 404
        
        # Verificar disponibilidad (excluyendo la reserva actual)
        cursor.execute("""
            SELECT 1 FROM Reservas 
            WHERE cancha_id = %s AND fecha_reserva = %s 
            AND reserva_id != %s
            AND (
                (hora_inicio < %s AND hora_fin > %s) OR
                (hora_inicio >= %s AND hora_inicio < %s) OR
                (hora_fin > %s AND hora_fin <= %s)
            )
            AND estado IN ('pendiente', 'confirmada')
        """, (court_id, date, reservation_id, end_time, start_time, start_time, end_time, start_time, end_time))
        
        if cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "La cancha no está disponible en ese horario"}), 400
        
        # Actualizar reserva
        cursor.execute("""
            UPDATE Reservas SET
                usuario_id = %s,
                cancha_id = %s,
                fecha_reserva = %s,
                hora_inicio = %s,
                hora_fin = %s,
                estado = %s
            WHERE reserva_id = %s
        """, (user_id, court_id, date, start_time, end_time, status, reservation_id))
        
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        
        if affected == 0:
            return jsonify({"success": False, "message": "No se pudo actualizar la reserva"}), 400
        
        return jsonify({
            "success": True,
            "message": "Reserva actualizada exitosamente"
        })
        
    except Exception as e:
        print(f"Error al actualizar reserva: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al actualizar reserva"}), 500
    
##------------------Endpoints para Gestión de Canchas------------------###
@app.route('/api/courts', methods=['GET'])
@token_required
def get_courts(current_user):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT cancha_id as id, nombre as name, descripcion as description,
               precio_hora as price, imagen_url as image, estado as status,
               CASE 
                   WHEN estado = 'disponible' THEN 'Activa'
                   WHEN estado = 'mantenimiento' THEN 'En Mantenimiento'
                   WHEN estado = 'inactiva' THEN 'Inactiva'
               END as status_text
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
               precio_hora as price, imagen_url as image, estado as status
        FROM Canchas
        WHERE cancha_id = %s
    """, (court_id,))
    
    court = cursor.fetchone()
    
    if not court:
        conn.close()
        return jsonify({"success": False, "message": "Cancha no encontrada"}), 404
    
    conn.close()
    return jsonify({"success": True, "court": court})

@app.route('/api/courts', methods=['POST'])
@token_required
def create_court(current_user):
    try:
        data = request.form
        
        required_fields = ['name', 'description', 'price']
        if not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
        
        name = data['name']
        description = data['description']
        price = float(data['price'])
        status = data.get('status', 'disponible')
        
        # Procesar imagen si se envió
        image_url = None
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file.filename != '':
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                image_url = f"/uploads/{filename}"
        
        conn = conectar()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO Canchas (nombre, descripcion, precio_hora, imagen_url, estado)
            VALUES (%s, %s, %s, %s, %s)
        """, (name, description, price, image_url, status))
        
        conn.commit()
        court_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Cancha creada exitosamente",
            "courtId": court_id
        })
        
    except Exception as e:
        print(f"Error al crear cancha: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al crear cancha"}), 500

@app.route('/api/courts/<int:court_id>', methods=['PUT'])
@token_required
def update_court(current_user, court_id):
    try:
        data = request.form
        
        required_fields = ['name', 'description', 'price']
        if not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
        
        name = data['name']
        description = data['description']
        price = float(data['price'])
        status = data.get('status', 'disponible')
        
        # Procesar imagen si se envió
        image_url = None
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file.filename != '':
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                image_url = f"/uploads/{filename}"
        
        conn = conectar()
        cursor = conn.cursor()
        
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
                    precio_hora = %s,
                    imagen_url = %s,
                    estado = %s
                WHERE cancha_id = %s
            """, (name, description, price, image_url, status, court_id))
        else:
            cursor.execute("""
                UPDATE Canchas SET
                    nombre = %s,
                    descripcion = %s,
                    precio_hora = %s,
                    estado = %s
                WHERE cancha_id = %s
            """, (name, description, price, status, court_id))
        
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

@app.route('/api/courts/<int:court_id>', methods=['DELETE'])
@token_required
def delete_court(current_user, court_id):
    conn = conectar()
    cursor = conn.cursor()
    
    # Verificar si la cancha tiene reservas futuras
    cursor.execute("""
        SELECT 1 FROM Reservas 
        WHERE cancha_id = %s AND fecha_reserva >= CURDATE()
        AND estado IN ('pendiente', 'confirmada')
    """, (court_id,))
    
    if cursor.fetchone():
        conn.close()
        return jsonify({
            "success": False, 
            "message": "No se puede eliminar la cancha porque tiene reservas futuras"
        }), 400
    
    # Eliminar cancha
    cursor.execute("DELETE FROM Canchas WHERE cancha_id = %s", (court_id,))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    
    if affected == 0:
        return jsonify({"success": False, "message": "Cancha no encontrada"}), 404
    
    return jsonify({"success": True, "message": "Cancha eliminada exitosamente"})

##------------------Endpoints para Gestión de Usuarios------------------###
@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    name_filter = request.args.get('name')
    email_filter = request.args.get('email')
    status_filter = request.args.get('status')
    
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
               estado as status,
               CASE 
                   WHEN estado = 'activo' THEN 'Activo'
                   ELSE 'Bloqueado'
               END as status_text,
               DATE_FORMAT(created_at, '%%d/%%m/%%Y') as registration_date,
               (SELECT COUNT(*) FROM Reservas WHERE usuario_id = usuario_id) as reservations_count
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
    if status_filter:
        conditions.append("estado = %s")
        params.append(status_filter)
    
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
               documento_numero as document, rol as role, estado as status,
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

@app.route('/api/users', methods=['POST'])
@token_required
def create_user(current_user):
    data = request.get_json()
    
    required_fields = ['name', 'email', 'password', 'role', 'status']
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
    
    try:
        name = data['name']
        email = data['email']
        password = data['password']
        role = data['role']
        status = data['status']
        document = data.get('document')
        
        if role == 'admin' and not document:
            return jsonify({"success": False, "message": "Los administradores deben tener documento"}), 400
        
        # Validar email único
        conn = conectar()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM Usuarios WHERE email = %s", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "El email ya está registrado"}), 400
        
        # Hash de contraseña
        salt, hashed_password = hash_password(password)
        
        # Crear usuario
        cursor.execute("""
            INSERT INTO Usuarios (
                nombre, email, password_hash, salt, rol, estado, documento_numero
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (name, email, hashed_password, salt, role, status, document))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Usuario creado exitosamente",
            "userId": user_id
        })
        
    except Exception as e:
        print(f"Error al crear usuario: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al crear usuario"}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    data = request.get_json()
    
    required_fields = ['name', 'email', 'role', 'status']
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
    
    try:
        name = data['name']
        email = data['email']
        role = data['role']
        status = data['status']
        document = data.get('document')
        password = data.get('password')
        
        if role == 'admin' and not document:
            return jsonify({"success": False, "message": "Los administradores deben tener documento"}), 400
        
        conn = conectar()
        cursor = conn.cursor()
        
        # Verificar si el usuario existe
        cursor.execute("SELECT 1 FROM Usuarios WHERE usuario_id = %s", (user_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Usuario no encontrado"}), 404
        
        # Verificar email único (excluyendo el usuario actual)
        cursor.execute("SELECT 1 FROM Usuarios WHERE email = %s AND usuario_id != %s", (email, user_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "El email ya está registrado"}), 400
        
        # Actualizar usuario
        if password:
            salt, hashed_password = hash_password(password)
            cursor.execute("""
                UPDATE Usuarios SET
                    nombre = %s,
                    email = %s,
                    password_hash = %s,
                    salt = %s,
                    rol = %s,
                    estado = %s,
                    documento_numero = %s
                WHERE usuario_id = %s
            """, (name, email, hashed_password, salt, role, status, document, user_id))
        else:
            cursor.execute("""
                UPDATE Usuarios SET
                    nombre = %s,
                    email = %s,
                    rol = %s,
                    estado = %s,
                    documento_numero = %s
                WHERE usuario_id = %s
            """, (name, email, role, status, document, user_id))
        
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        
        if affected == 0:
            return jsonify({"success": False, "message": "No se pudo actualizar el usuario"}), 400
        
        return jsonify({
            "success": True,
            "message": "Usuario actualizado exitosamente"
        })
        
    except Exception as e:
        print(f"Error al actualizar usuario: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al actualizar usuario"}), 500

@app.route('/api/users/<int:user_id>/block', methods=['PUT'])
@token_required
def block_user(current_user, user_id):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE Usuarios 
        SET estado = 'bloqueado' 
        WHERE usuario_id = %s AND estado = 'activo'
    """, (user_id,))
    
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    
    if affected == 0:
        return jsonify({"success": False, "message": "Usuario no encontrado o ya bloqueado"}), 404
    
    return jsonify({"success": True, "message": "Usuario bloqueado exitosamente"})

@app.route('/api/users/<int:user_id>/activate', methods=['PUT'])
@token_required
def activate_user(current_user, user_id):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE Usuarios 
        SET estado = 'activo' 
        WHERE usuario_id = %s AND estado = 'bloqueado'
    """, (user_id,))
    
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    
    if affected == 0:
        return jsonify({"success": False, "message": "Usuario no encontrado o ya activo"}), 404
    
    return jsonify({"success": True, "message": "Usuario activado exitosamente"})

##------------------Endpoints para Estadísticas------------------###
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

##------------------Endpoints para Notificaciones------------------###
@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    conn = conectar()
    cursor = conn.cursor()
    
    # Contar total para paginación
    cursor.execute("SELECT COUNT(*) as total FROM Notificaciones")
    total = cursor.fetchone()['total']
    
    # Obtener notificaciones
    cursor.execute("""
        SELECT notificacion_id as id, titulo as title, contenido as content,
               destinatarios as recipients, fecha_envio as date,
               CASE 
                   WHEN destinatarios = 'all' THEN 'Todos los usuarios'
                   WHEN destinatarios = 'active' THEN 'Usuarios activos'
                   WHEN destinatarios = 'with-reservations' THEN 'Usuarios con reservas'
                   WHEN destinatarios = 'specific' THEN 'Usuarios específicos'
               END as recipients_text,
               DATE_FORMAT(fecha_envio, '%%d/%%m/%%Y %%H:%%i') as formatted_date
        FROM Notificaciones
        ORDER BY fecha_envio DESC
        LIMIT %s OFFSET %s
    """, (per_page, offset))
    
    notifications = cursor.fetchall()
    
    # Obtener usuarios para el selector
    cursor.execute("SELECT usuario_id as id, nombre as name FROM Usuarios")
    users = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        "success": True,
        "notifications": notifications,
        "total": total,
        "users": users
    })

@app.route('/api/notifications/<int:notification_id>', methods=['GET'])
@token_required
def get_notification(current_user, notification_id):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT notificacion_id as id, titulo as title, contenido as content,
               destinatarios as recipients, fecha_envio as date,
               usuarios_especificos as specific_users,
               tipo as type,
               CASE 
                   WHEN destinatarios = 'all' THEN 'Todos los usuarios'
                   WHEN destinatarios = 'active' THEN 'Usuarios activos'
                   WHEN destinatarios = 'with-reservations' THEN 'Usuarios con reservas'
                   WHEN destinatarios = 'specific' THEN 'Usuarios específicos'
               END as recipients_text,
               CASE 
                   WHEN tipo = 'general' THEN 'General'
                   WHEN tipo = 'promotion' THEN 'Promoción'
                   WHEN tipo = 'important' THEN 'Importante'
               END as type_text,
               DATE_FORMAT(fecha_envio, '%%d/%%m/%%Y %%H:%%i') as formatted_date
        FROM Notificaciones
        WHERE notificacion_id = %s
    """, (notification_id,))
    
    notification = cursor.fetchone()
    
    if not notification:
        conn.close()
        return jsonify({"success": False, "message": "Notificación no encontrada"}), 404
    
    conn.close()
    return jsonify({"success": True, "notification": notification})

@app.route('/api/notifications', methods=['POST'])
@token_required
def create_notification(current_user):
    data = request.get_json()
    
    required_fields = ['title', 'content', 'recipients', 'type']
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
    
    try:
        title = data['title']
        content = data['content']
        recipients = data['recipients']
        type = data['type']
        specific_users = data.get('specificUsers', [])
        
        conn = conectar()
        cursor = conn.cursor()
        
        # Crear notificación
        cursor.execute("""
            INSERT INTO Notificaciones (
                titulo, contenido, destinatarios, tipo, usuarios_especificos
            ) VALUES (%s, %s, %s, %s, %s)
        """, (title, content, recipients, type, json.dumps(specific_users) if specific_users else None))
        
        conn.commit()
        notification_id = cursor.lastrowid
        
        # Enviar notificaciones a los usuarios (simulado)
        if recipients == 'all':
            cursor.execute("SELECT usuario_id as id FROM Usuarios")
            users = [u['id'] for u in cursor.fetchall()]
        elif recipients == 'active':
            cursor.execute("SELECT usuario_id as id FROM Usuarios WHERE estado = 'activo'")
            users = [u['id'] for u in cursor.fetchall()]
        elif recipients == 'with-reservations':
            cursor.execute("SELECT DISTINCT usuario_id as id FROM Reservas")
            users = [u['id'] for u in cursor.fetchall()]
        elif recipients == 'specific':
            users = specific_users
        
        # Registrar envío (simulado)
        for user_id in users:
            cursor.execute("""
                INSERT INTO NotificacionesUsuarios (
                    notificacion_id, usuario_id, estado
                ) VALUES (%s, %s, 'enviada')
            """, (notification_id, user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Notificación enviada exitosamente",
            "notificationId": notification_id
        })
        
    except Exception as e:
        print(f"Error al enviar notificación: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al enviar notificación"}), 500

@app.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
@token_required
def delete_notification(current_user, notification_id):
    conn = conectar()
    cursor = conn.cursor()
    
    # Eliminar notificación
    cursor.execute("DELETE FROM Notificaciones WHERE notificacion_id = %s", (notification_id,))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    
    if affected == 0:
        return jsonify({"success": False, "message": "Notificación no encontrada"}), 404
    
    return jsonify({"success": True, "message": "Notificación eliminada exitosamente"})

##------------------Endpoints para Configuración------------------###
@app.route('/api/settings', methods=['GET'])
@token_required
def get_settings(current_user):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT nombre_sitio as siteName, email_contacto as contactEmail,
               telefono_contacto as contactPhone, horario_atencion as businessHours,
               direccion as businessAddress,
               plantilla_reserva_confirmada as confirmedReservationTemplate
        FROM Configuracion
        LIMIT 1
    """)
    
    settings = cursor.fetchone()
    
    if not settings:
        # Configuración por defecto
        settings = {
            "siteName": "ReservaCanchas",
            "contactEmail": "contacto@reservacanchas.com",
            "contactPhone": "+123456789",
            "businessHours": "Lunes a Viernes: 9:00 - 18:00",
            "businessAddress": "Av. Principal 123, Ciudad",
            "confirmedReservationTemplate": "Su reserva ha sido confirmada para el {fecha} a las {hora} en la cancha {cancha}."
        }
    
    conn.close()
    return jsonify({
        "success": True,
        "settings": settings
    })

@app.route('/api/settings', methods=['PUT'])
@token_required
def update_settings(current_user):
    data = request.get_json()
    
    required_fields = ['siteName', 'contactEmail', 'contactPhone', 'businessHours', 'businessAddress']
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
    
    try:
        site_name = data['siteName']
        contact_email = data['contactEmail']
        contact_phone = data['contactPhone']
        business_hours = data['businessHours']
        business_address = data['businessAddress']
        
        conn = conectar()
        cursor = conn.cursor()
        
        # Verificar si ya existe configuración
        cursor.execute("SELECT 1 FROM Configuracion")
        if cursor.fetchone():
            # Actualizar configuración existente
            cursor.execute("""
                UPDATE Configuracion SET
                    nombre_sitio = %s,
                    email_contacto = %s,
                    telefono_contacto = %s,
                    horario_atencion = %s,
                    direccion = %s
            """, (site_name, contact_email, contact_phone, business_hours, business_address))
        else:
            # Insertar nueva configuración
            cursor.execute("""
                INSERT INTO Configuracion (
                    nombre_sitio, email_contacto, telefono_contacto, 
                    horario_atencion, direccion
                ) VALUES (%s, %s, %s, %s, %s)
            """, (site_name, contact_email, contact_phone, business_hours, business_address))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Configuración actualizada exitosamente"
        })
        
    except Exception as e:
        print(f"Error al actualizar configuración: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al actualizar configuración"}), 500

@app.route('/api/settings/notification', methods=['PUT'])
@token_required
def update_notification_template(current_user):
    data = request.get_json()
    
    if 'template' not in data:
        return jsonify({"success": False, "message": "Plantilla requerida"}), 400
    
    try:
        template = data['template']
        
        conn = conectar()
        cursor = conn.cursor()
        
        # Verificar si ya existe configuración
        cursor.execute("SELECT 1 FROM Configuracion")
        if cursor.fetchone():
            # Actualizar plantilla
            cursor.execute("""
                UPDATE Configuracion SET
                    plantilla_reserva_confirmada = %s
            """, (template,))
        else:
            # Insertar nueva configuración con plantilla
            cursor.execute("""
                INSERT INTO Configuracion (
                    plantilla_reserva_confirmada
                ) VALUES (%s)
            """, (template,))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Plantilla de notificación actualizada"
        })
        
    except Exception as e:
        print(f"Error al actualizar plantilla: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al actualizar plantilla"}), 500
    
##------------------Endpoints para Perfil de Administrador------------------###
@app.route('/api/admin/profile', methods=['GET'])
@token_required
def get_admin_profile(current_user):
    conn = conectar()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT usuario_id as id, nombre as name, email, 
               documento_numero as document, telefono as phone,
               imagen_perfil as profileImage,
               DATE_FORMAT(ultimo_acceso, '%%d/%%m/%%Y %%H:%%i') as lastAccess,
               ip_ultimo_acceso as ip
        FROM Usuarios
        WHERE usuario_id = %s
    """, (current_user,))
    
    profile = cursor.fetchone()
    
    if not profile:
        conn.close()
        return jsonify({"success": False, "message": "Perfil no encontrado"}), 404
    
    conn.close()
    return jsonify({"success": True, "profile": profile})

@app.route('/api/admin/profile', methods=['PUT'])
@token_required
def update_admin_profile(current_user):
    data = request.get_json()
    
    required_fields = ['name', 'email', 'phone']
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
    
    try:
        name = data['name']
        email = data['email']
        phone = data['phone']
        
        conn = conectar()
        cursor = conn.cursor()
        
        # Verificar email único (excluyendo el usuario actual)
        cursor.execute("SELECT 1 FROM Usuarios WHERE email = %s AND usuario_id != %s", (email, current_user))
        if cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "El email ya está registrado"}), 400
        
        # Actualizar perfil
        cursor.execute("""
            UPDATE Usuarios SET
                nombre = %s,
                email = %s,
                telefono = %s
            WHERE usuario_id = %s
        """, (name, email, phone, current_user))
        
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        
        if affected == 0:
            return jsonify({"success": False, "message": "No se pudo actualizar el perfil"}), 400
        
        return jsonify({
            "success": True,
            "message": "Perfil actualizado exitosamente"
        })
        
    except Exception as e:
        print(f"Error al actualizar perfil: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al actualizar perfil"}), 500

@app.route('/api/admin/password', methods=['PUT'])
@token_required
def update_admin_password(current_user):
    data = request.get_json()
    
    required_fields = ['currentPassword', 'newPassword']
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "message": "Faltan campos requeridos"}), 400
    
    try:
        current_password = data['currentPassword']
        new_password = data['newPassword']
        
        if len(new_password) < 6:
            return jsonify({"success": False, "message": "La contraseña debe tener al menos 6 caracteres"}), 400
        
        conn = conectar()
        cursor = conn.cursor()
        
        # Obtener usuario y verificar contraseña actual
        cursor.execute("SELECT password_hash, salt FROM Usuarios WHERE usuario_id = %s", (current_user,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({"success": False, "message": "Usuario no encontrado"}), 404
        
        # Verificar contraseña actual
        _, hashed_password = hash_password(current_password, user['salt'])
        if hashed_password != user['password_hash']:
            conn.close()
            return jsonify({"success": False, "message": "Contraseña actual incorrecta"}), 401
        
        # Generar nuevo hash de contraseña
        salt, new_hashed_password = hash_password(new_password)
        
        # Actualizar contraseña
        cursor.execute("""
            UPDATE Usuarios SET
                password_hash = %s,
                salt = %s
            WHERE usuario_id = %s
        """, (new_hashed_password, salt, current_user))
        
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        
        if affected == 0:
            return jsonify({"success": False, "message": "No se pudo actualizar la contraseña"}), 400
        
        return jsonify({
            "success": True,
            "message": "Contraseña actualizada exitosamente"
        })
        
    except Exception as e:
        print(f"Error al actualizar contraseña: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al actualizar contraseña"}), 500

@app.route('/api/admin/profile/image', methods=['POST'])
@token_required
def update_admin_profile_image(current_user):
    try:
        if 'image' not in request.files:
            return jsonify({"success": False, "message": "No se proporcionó imagen"}), 400
        
        image_file = request.files['image']
        if image_file.filename == '':
            return jsonify({"success": False, "message": "No se seleccionó archivo"}), 400
        
        # Guardar imagen
        filename = secure_filename(f"profile_{current_user}_{image_file.filename}")
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(image_path)
        image_url = f"/uploads/{filename}"
        
        # Actualizar en base de datos
        conn = conectar()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE Usuarios SET
                imagen_perfil = %s
            WHERE usuario_id = %s
        """, (image_url, current_user))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Imagen de perfil actualizada",
            "imageUrl": image_url
        })
        
    except Exception as e:
        print(f"Error al actualizar imagen de perfil: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return jsonify({"success": False, "message": "Error al actualizar imagen de perfil"}), 500

@app.route('/api/admin/profile/image', methods=['DELETE'])
@token_required
def delete_admin_profile_image(current_user):
    conn = conectar()
    cursor = conn.cursor()
    
    # Eliminar imagen de perfil
    cursor.execute("""
        UPDATE Usuarios SET
            imagen_perfil = NULL
        WHERE usuario_id = %s
    """, (current_user,))
    
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    
    if affected == 0:
        return jsonify({"success": False, "message": "No se pudo eliminar la imagen de perfil"}), 400
    
    return jsonify({"success": True, "message": "Imagen de perfil eliminada"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)