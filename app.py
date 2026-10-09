import os
from datetime import datetime, timezone, timedelta
from functools import wraps
from io import BytesIO
from dotenv import load_dotenv

from flask import (
    Flask, render_template, request, redirect, url_for, send_file, session, flash,
)
from flask_sqlalchemy import SQLAlchemy
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
database_url = os.environ.get("DATABASE_URL", "sqlite:///puesto.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
# Clave para firmar las sesiones. En internet se define con una variable de entorno.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "clave-solo-para-pruebas-locales")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
db = SQLAlchemy(app)

# Guatemala está en UTC-6 todo el año
ZONA_GT = timezone(timedelta(hours=-6))


def ahora():
    return datetime.now(ZONA_GT).replace(tzinfo=None)


# ---------- Tablas de la base de datos ----------
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(50), unique=True, nullable=False)
    clave_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(20), nullable=False, default="empleado")  # admin o empleado
    activo = db.Column(db.Boolean, default=True)


class Producto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    precio = db.Column(db.Float, nullable=False)
    activo = db.Column(db.Boolean, default=True)


class Pedido(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha_hora = db.Column(db.DateTime, default=ahora)
    tomado_por = db.Column(db.String(50), default="")
    total = db.Column(db.Float, default=0)
    detalles = db.relationship("DetallePedido", backref="pedido")


class DetallePedido(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pedido_id = db.Column(db.Integer, db.ForeignKey("pedido.id"), nullable=False)
    producto_id = db.Column(db.Integer, db.ForeignKey("producto.id"), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    precio_vendido = db.Column(db.Float, nullable=False)
    producto = db.relationship("Producto")


with app.app_context():
    db.create_all()


# ---------- Control de acceso ----------
def usuario_actual():
    """Devuelve el usuario que inició sesión, o None si no hay uno válido."""
    uid = session.get("usuario_id")
    if uid is None:
        return None
    u = db.session.get(Usuario, uid)
    if u is None or not u.activo:
        session.clear()
        return None
    return u


def login_requerido(f):
    @wraps(f)
    def envoltura(*args, **kwargs):
        if usuario_actual() is None:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return envoltura


def admin_requerido(f):
    @wraps(f)
    def envoltura(*args, **kwargs):
        u = usuario_actual()
        if u is None:
            return redirect(url_for("login"))
        if u.rol != "admin":
            return redirect(url_for("nuevo_pedido"))
        return f(*args, **kwargs)

    return envoltura


@app.before_request
def verificar_configuracion():
    # Si todavía no existe ningún usuario, hay que crear el administrador
    if request.endpoint in (None, "static", "configurar"):
        return
    if Usuario.query.first() is None:
        return redirect(url_for("configurar"))


@app.route("/configurar", methods=["GET", "POST"])
def configurar():
    # Esta pantalla solo funciona mientras no exista ningún usuario
    if Usuario.query.first() is not None:
        return redirect(url_for("login"))
    if request.method == "POST":
        nombre = request.form["usuario"].strip().lower()
        clave = request.form["clave"]
        confirmar = request.form["confirmar"]
        if not nombre:
            flash("Escribe un nombre de usuario.")
        elif len(clave) < 6:
            flash("La contraseña debe tener al menos 6 caracteres.")
        elif clave != confirmar:
            flash("Las contraseñas no coinciden.")
        else:
            db.session.add(
                Usuario(usuario=nombre, clave_hash=generate_password_hash(clave), rol="admin")
            )
            db.session.commit()
            flash("Administrador creado. Ya puedes iniciar sesión.")
            return redirect(url_for("login"))
    return render_template("configurar.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nombre = request.form["usuario"].strip().lower()
        clave = request.form["clave"]
        u = Usuario.query.filter_by(usuario=nombre).first()
        if u and u.activo and check_password_hash(u.clave_hash, clave):
            session.clear()
            session.permanent = True
            session["usuario_id"] = u.id
            session["usuario"] = u.usuario
            session["rol"] = u.rol
            return redirect(url_for("inicio"))
        flash("Usuario o contraseña incorrectos.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def inicio():
    return redirect(url_for("nuevo_pedido"))


# ---------- Usuarios (solo administrador) ----------
@app.route("/usuarios")
@admin_requerido
def usuarios():
    lista = Usuario.query.order_by(Usuario.usuario).all()
    return render_template("usuarios.html", usuarios=lista)


@app.route("/usuarios/agregar", methods=["POST"])
@admin_requerido
def agregar_usuario():
    nombre = request.form["usuario"].strip().lower()
    clave = request.form["clave"]
    rol = request.form.get("rol", "empleado")
    if rol not in ("admin", "empleado"):
        rol = "empleado"
    if not nombre:
        flash("Escribe un nombre de usuario.")
    elif len(clave) < 6:
        flash("La contraseña debe tener al menos 6 caracteres.")
    elif Usuario.query.filter_by(usuario=nombre).first():
        flash("Ese nombre de usuario ya existe.")
    else:
        db.session.add(
            Usuario(usuario=nombre, clave_hash=generate_password_hash(clave), rol=rol)
        )
        db.session.commit()
        flash(f"Usuario '{nombre}' creado.")
    return redirect(url_for("usuarios"))


@app.route("/usuarios/<int:id>/clave", methods=["POST"])
@admin_requerido
def cambiar_clave(id):
    u = db.get_or_404(Usuario, id)
    clave = request.form["clave"]
    if len(clave) < 6:
        flash("La contraseña debe tener al menos 6 caracteres.")
    else:
        u.clave_hash = generate_password_hash(clave)
        db.session.commit()
        flash(f"Contraseña de '{u.usuario}' actualizada.")
    return redirect(url_for("usuarios"))


@app.route("/usuarios/<int:id>/activar", methods=["POST"])
@admin_requerido
def activar_usuario(id):
    u = db.get_or_404(Usuario, id)
    if u.id == session.get("usuario_id"):
        flash("No puedes desactivar tu propia cuenta.")
    else:
        u.activo = not u.activo
        db.session.commit()
    return redirect(url_for("usuarios"))


# ---------- Productos (solo administrador) ----------
@app.route("/productos")
@admin_requerido
def productos():
    lista = Producto.query.order_by(Producto.nombre).all()
    return render_template("productos.html", productos=lista)


@app.route("/productos/agregar", methods=["POST"])
@admin_requerido
def agregar():
    nombre = request.form["nombre"].strip()
    precio = float(request.form["precio"])
    if nombre:
        db.session.add(Producto(nombre=nombre, precio=precio))
        db.session.commit()
    return redirect(url_for("productos"))


@app.route("/productos/<int:id>/actualizar", methods=["POST"])
@admin_requerido
def actualizar(id):
    p = db.get_or_404(Producto, id)
    p.nombre = request.form["nombre"].strip()
    p.precio = float(request.form["precio"])
    db.session.commit()
    return redirect(url_for("productos"))


@app.route("/productos/<int:id>/activar", methods=["POST"])
@admin_requerido
def activar(id):
    p = db.get_or_404(Producto, id)
    p.activo = not p.activo
    db.session.commit()
    return redirect(url_for("productos"))


# ---------- Pedidos (administrador y empleados) ----------
@app.route("/pedido/nuevo")
@login_requerido
def nuevo_pedido():
    activos = Producto.query.filter_by(activo=True).order_by(Producto.nombre).all()
    return render_template("nuevo_pedido.html", productos=activos)


@app.route("/pedido/guardar", methods=["POST"])
@login_requerido
def guardar_pedido():
    activos = Producto.query.filter_by(activo=True).all()
    detalles = []
    total = 0
    for p in activos:
        texto = request.form.get(f"cantidad_{p.id}", "0")
        cantidad = int(texto) if texto.isdigit() else 0
        if cantidad > 0:
            detalles.append(
                DetallePedido(producto_id=p.id, cantidad=cantidad, precio_vendido=p.precio)
            )
            total += cantidad * p.precio
    if not detalles:
        return redirect(url_for("nuevo_pedido"))
    pedido = Pedido(total=total, detalles=detalles, tomado_por=usuario_actual().usuario)
    db.session.add(pedido)
    db.session.commit()
    u = usuario_actual()
    if u.rol == "admin":
        return redirect(url_for("ventas_hoy"))
    flash("Pedido guardado.")
    return redirect(url_for("nuevo_pedido"))


# ---------- Ventas del día (solo administrador) ----------
@app.route("/ventas")
@admin_requerido
def ventas_hoy():
    hoy = ahora().date()
    inicio_dia = datetime.combine(hoy, datetime.min.time())
    fin_dia = inicio_dia + timedelta(days=1)
    pedidos = (
        Pedido.query.filter(Pedido.fecha_hora >= inicio_dia, Pedido.fecha_hora < fin_dia)
        .order_by(Pedido.fecha_hora.desc())
        .all()
    )
    total_dia = sum(p.total for p in pedidos)
    return render_template("ventas.html", pedidos=pedidos, total_dia=total_dia, fecha=hoy)


# ---------- PDF de ventas del día (solo administrador) ----------
@app.route("/reporte/pdf")
@admin_requerido
def reporte_pdf():
    # 1. Tomar la fecha que eligió el usuario (si no viene, usar hoy)
    texto = request.args.get("fecha", "")
    try:
        dia = datetime.strptime(texto, "%Y-%m-%d").date()
    except ValueError:
        dia = ahora().date()

    inicio_dia = datetime.combine(dia, datetime.min.time())
    fin_dia = inicio_dia + timedelta(days=1)

    # 2. Buscar los pedidos de ese día
    pedidos = Pedido.query.filter(
        Pedido.fecha_hora >= inicio_dia, Pedido.fecha_hora < fin_dia
    ).all()

    # 3. Sumar las cantidades por plato (y por precio vendido)
    resumen = {}
    for pedido in pedidos:
        for d in pedido.detalles:
            clave = (d.producto.nombre, d.precio_vendido)
            resumen[clave] = resumen.get(clave, 0) + d.cantidad
    filas = sorted(resumen.items())

    # 4. Armar la tabla
    datos = [["Plato", "Cantidad vendida", "Precio (Q)", "Total (Q)"]]
    total_cantidad = 0
    total_dia = 0
    for (nombre, precio), cantidad in filas:
        subtotal = cantidad * precio
        datos.append([nombre, str(cantidad), f"{precio:.2f}", f"{subtotal:.2f}"])
        total_cantidad += cantidad
        total_dia += subtotal
    datos.append(["Total del día", str(total_cantidad), "", f"{total_dia:.2f}"])

    # 5. Crear el PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title=f"Ventas {dia}")
    estilos = getSampleStyleSheet()
    elementos = [
        Paragraph("Ventas del día", estilos["Title"]),
        Paragraph(f"Fecha: {dia.strftime('%d/%m/%Y')}", estilos["Normal"]),
        Paragraph(f"Número de pedidos: {len(pedidos)}", estilos["Normal"]),
        Spacer(1, 12),
    ]

    if not filas:
        elementos.append(
            Paragraph("No hay ventas registradas en esta fecha.", estilos["Normal"])
        )
    else:
        tabla = Table(datos, repeatRows=1, colWidths=[200, 110, 90, 90])
        tabla.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7B3F00")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
                    ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#F3E5D0")),
                    ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
                ]
            )
        )
        elementos.append(tabla)

    doc.build(elementos)
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"ventas_{dia}.pdf",
    )


if __name__ == "__main__":
    app.run(debug=True)