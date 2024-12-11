const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const path = require('path');
const multer = require('multer');
require('dotenv').config();

const app = express();

// Configuración de multer para el almacenamiento de imágenes
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/')
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname)
    }
});

const upload = multer({ storage: storage });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 horas
    }
}));

// Database connection
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}).promise();

// Middleware de autenticación
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ error: 'No autenticado' });
    }
};

const isAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.rol === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Acceso denegado - Se requiere rol de administrador' });
    }
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/productos', async (req, res) => {
    try {
        const [productos] = await pool.query('SELECT * FROM productos WHERE status = "activo"');
        res.json(productos);
    } catch (error) {
        console.error('Error al obtener productos:', error);
        res.status(500).json({ error: 'Error al obtener productos' });
    }
});

// Obtener todos los productos (incluyendo inactivos) para el admin
app.get('/admin/productos/todos', isAdmin, async (req, res) => {
    try {
        const [productos] = await pool.query('SELECT * FROM productos ORDER BY id_producto DESC');
        res.json({ success: true, productos });
    } catch (error) {
        console.error('Error al obtener productos:', error);
        res.status(500).json({ success: false, error: 'Error al obtener productos' });
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { correo, password } = req.body;
    try {
        const [users] = await pool.query('SELECT * FROM usuarios WHERE correo_usuario = ? AND contraseña = ?', [correo, password]);
        if (users.length > 0) {
            req.session.user = users[0];
            // Determinar la redirección basada en el rol
            const redirect = users[0].rol === 'admin' ? '/admin.html' : '/productos.html';
            res.json({ 
                success: true, 
                role: users[0].rol,
                redirect: redirect
            });
        } else {
            res.status(401).json({ 
                success: false, 
                message: 'Credenciales inválidas' 
            });
        }
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error en el servidor' 
        });
    }
});

// Ruta de logout
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Error al cerrar sesión' });
        }
        res.json({ success: true, message: 'Sesión cerrada correctamente' });
    });
});

// Ruta para verificar estado de autenticación
app.get('/check-auth', (req, res) => {
    if (req.session.user) {
        res.json({ 
            isAuthenticated: true,
            isAdmin: req.session.user.rol === 'admin',
            user: {
                id: req.session.user.id_usuario,
                nombre: req.session.user.nombre,
                rol: req.session.user.rol
            }
        });
    } else {
        res.json({ 
            isAuthenticated: false,
            isAdmin: false 
        });
    }
});

// Admin: Add product
app.post('/admin/productos', isAdmin, upload.single('imagen'), async (req, res) => {
    const { nombre_producto, precio, descripcion, marca_producto, proveedor, stock } = req.body;
    const imagen_producto = req.file ? req.file.filename : null;
    
    try {
        const [result] = await pool.query(
            'INSERT INTO productos (nombre_producto, imagen_producto, precio, descripcion, marca_producto, proveedor, stock, status) VALUES (?, ?, ?, ?, ?, ?, ?, "activo")',
            [nombre_producto, imagen_producto, precio, descripcion, marca_producto, proveedor, stock]
        );
        res.json({ success: true, id: result.insertId, message: 'Producto agregado correctamente' });
    } catch (error) {
        console.error('Error al agregar producto:', error);
        res.status(500).json({ success: false, error: 'Error al agregar producto' });
    }
});

// Admin: Update product
app.put('/admin/productos/:id', isAdmin, upload.single('imagen'), async (req, res) => {
    const { id } = req.params;
    const { nombre_producto, precio, descripcion, marca_producto, proveedor, stock } = req.body;
    
    try {
        let query = 'UPDATE productos SET nombre_producto = ?, precio = ?, descripcion = ?, marca_producto = ?, proveedor = ?, stock = ?';
        let params = [nombre_producto, precio, descripcion, marca_producto, proveedor, stock];

        if (req.file) {
            query += ', imagen_producto = ?';
            params.push(req.file.filename);
        }

        query += ' WHERE id_producto = ?';
        params.push(id);

        await pool.query(query, params);
        res.json({ success: true, message: 'Producto actualizado correctamente' });
    } catch (error) {
        console.error('Error al actualizar producto:', error);
        res.status(500).json({ success: false, error: 'Error al actualizar producto' });
    }
});

// Admin: Delete product (soft delete)
app.delete('/admin/productos/:id', isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('UPDATE productos SET status = "inactivo" WHERE id_producto = ?', [id]);
        res.json({ success: true, message: 'Producto eliminado correctamente' });
    } catch (error) {
        console.error('Error al eliminar producto:', error);
        res.status(500).json({ success: false, error: 'Error al eliminar producto' });
    }
});

// Admin: Restaurar producto
app.put('/admin/productos/restaurar/:id', isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('UPDATE productos SET status = "activo" WHERE id_producto = ?', [id]);
        res.json({ success: true, message: 'Producto restaurado correctamente' });
    } catch (error) {
        console.error('Error al restaurar producto:', error);
        res.status(500).json({ success: false, error: 'Error al restaurar producto' });
    }
});

// Rutas para gestión de usuarios (admin)
app.get('/admin/usuarios', isAdmin, async (req, res) => {
    try {
        const [usuarios] = await pool.query('SELECT * FROM usuarios ORDER BY id_usuario DESC');
        res.json({ success: true, usuarios });
    } catch (error) {
        console.error('Error al obtener usuarios:', error);
        res.status(500).json({ success: false, error: 'Error al obtener usuarios' });
    }
});

app.post('/admin/usuarios', isAdmin, async (req, res) => {
    const { nombre, apellido, correo_usuario, contraseña, dni, rol } = req.body;
    try {
        // Verificar si el correo o DNI ya existen
        const [existente] = await pool.query(
            'SELECT * FROM usuarios WHERE correo_usuario = ? OR dni = ?',
            [correo_usuario, dni]
        );

        if (existente.length > 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'El correo o DNI ya están registrados' 
            });
        }

        const [result] = await pool.query(
            'INSERT INTO usuarios (nombre, apellido, correo_usuario, contraseña, dni, rol) VALUES (?, ?, ?, ?, ?, ?)',
            [nombre, apellido, correo_usuario, contraseña, dni, rol]
        );
        res.json({ 
            success: true, 
            id: result.insertId, 
            message: 'Usuario creado correctamente' 
        });
    } catch (error) {
        console.error('Error al crear usuario:', error);
        res.status(500).json({ success: false, error: 'Error al crear usuario' });
    }
});

app.put('/admin/usuarios/:id', isAdmin, async (req, res) => {
    const { id } = req.params;
    const { nombre, apellido, correo_usuario, contraseña, dni, rol } = req.body;
    try {
        // Verificar si el correo o DNI ya existen en otro usuario
        const [existente] = await pool.query(
            'SELECT * FROM usuarios WHERE (correo_usuario = ? OR dni = ?) AND id_usuario != ?',
            [correo_usuario, dni, id]
        );

        if (existente.length > 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'El correo o DNI ya están registrados por otro usuario' 
            });
        }

        let query = 'UPDATE usuarios SET nombre = ?, apellido = ?, correo_usuario = ?, dni = ?, rol = ?';
        let params = [nombre, apellido, correo_usuario, dni, rol];

        if (contraseña) {
            query += ', contraseña = ?';
            params.push(contraseña);
        }

        query += ' WHERE id_usuario = ?';
        params.push(id);

        await pool.query(query, params);
        res.json({ success: true, message: 'Usuario actualizado correctamente' });
    } catch (error) {
        console.error('Error al actualizar usuario:', error);
        res.status(500).json({ success: false, error: 'Error al actualizar usuario' });
    }
});

app.delete('/admin/usuarios/:id', isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        // Verificar si el usuario tiene ventas asociadas
        const [ventas] = await pool.query('SELECT * FROM ventas WHERE id_usuario = ?', [id]);
        if (ventas.length > 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'No se puede eliminar el usuario porque tiene ventas asociadas' 
            });
        }

        await pool.query('DELETE FROM usuarios WHERE id_usuario = ?', [id]);
        res.json({ success: true, message: 'Usuario eliminado correctamente' });
    } catch (error) {
        console.error('Error al eliminar usuario:', error);
        res.status(500).json({ success: false, error: 'Error al eliminar usuario' });
    }
});

// Rutas para gestión de ventas (admin)
app.get('/admin/ventas', isAdmin, async (req, res) => {
    try {
        const [ventas] = await pool.query(`
            SELECT v.*, u.nombre, u.apellido
            FROM ventas v
            JOIN usuarios u ON v.id_usuario = u.id_usuario
            ORDER BY v.fecha_venta DESC
        `);
        res.json({ success: true, ventas });
    } catch (error) {
        console.error('Error al obtener ventas:', error);
        res.status(500).json({ success: false, error: 'Error al obtener ventas' });
    }
});

app.get('/admin/ventas/:id', isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const [detalles] = await pool.query(`
            SELECT dv.*, p.nombre_producto
            FROM detalle_venta dv
            JOIN productos p ON dv.id_producto = p.id_producto
            WHERE dv.id_venta = ?
        `, [id]);
        res.json({ success: true, detalles });
    } catch (error) {
        console.error('Error al obtener detalles de venta:', error);
        res.status(500).json({ success: false, error: 'Error al obtener detalles de venta' });
    }
});

// Obtener productos activos con stock
app.get('/admin/productos/disponibles', isAdmin, async (req, res) => {
    try {
        const [productos] = await pool.query(
            'SELECT * FROM productos WHERE status = "activo" AND stock > 0 ORDER BY nombre_producto'
        );
        res.json({ success: true, productos });
    } catch (error) {
        console.error('Error al obtener productos:', error);
        res.status(500).json({ success: false, error: 'Error al obtener productos' });
    }
});

// Crear nueva venta con validación de stock y cálculo automático
app.post('/admin/ventas', isAdmin, async (req, res) => {
    const { id_usuario, productos } = req.body;
    const connection = await pool.getConnection();
    
    try {
        await connection.beginTransaction();

        // Verificar stock y calcular total
        let total = 0;
        const productosConPrecio = [];

        for (const prod of productos) {
            const [stockResult] = await connection.query(
                'SELECT id_producto, nombre_producto, stock, precio FROM productos WHERE id_producto = ? AND status = "activo"',
                [prod.id_producto]
            );

            if (stockResult.length === 0) {
                throw new Error(`Producto ${prod.id_producto} no encontrado o inactivo`);
            }

            const producto = stockResult[0];
            if (producto.stock < prod.cantidad) {
                throw new Error(`Stock insuficiente para ${producto.nombre_producto}. Stock disponible: ${producto.stock}`);
            }

            const subtotal = producto.precio * prod.cantidad;
            total += subtotal;

            productosConPrecio.push({
                ...prod,
                precio_unitario: producto.precio,
                subtotal: subtotal,
                nombre_producto: producto.nombre_producto
            });
        }

        // Crear la venta
        const [ventaResult] = await connection.query(
            'INSERT INTO ventas (id_usuario, total) VALUES (?, ?)',
            [id_usuario, total]
        );

        const id_venta = ventaResult.insertId;

        // Insertar detalles y actualizar stock
        for (const prod of productosConPrecio) {
            await connection.query(
                'INSERT INTO detalle_venta (id_venta, id_producto, cantidad, precio_unitario) VALUES (?, ?, ?, ?)',
                [id_venta, prod.id_producto, prod.cantidad, prod.precio_unitario]
            );

            await connection.query(
                'UPDATE productos SET stock = stock - ? WHERE id_producto = ?',
                [prod.cantidad, prod.id_producto]
            );
        }

        await connection.commit();
        res.json({ 
            success: true, 
            id: id_venta, 
            total: total,
            detalles: productosConPrecio,
            message: 'Venta registrada correctamente' 
        });
    } catch (error) {
        await connection.rollback();
        console.error('Error al crear venta:', error);
        res.status(500).json({ success: false, error: error.message });
    } finally {
        connection.release();
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
