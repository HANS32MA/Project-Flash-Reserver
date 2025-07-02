import pymysql

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