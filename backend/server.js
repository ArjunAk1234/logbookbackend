const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'attendance_db',
    password: process.env.DB_PASSWORD || 'newpassword',
    port: 5432,
});

const JWT_SECRET = process.env.JWT_SECRET || 'supreme_secret_999';
const generate6DigitToken = () => Math.floor(100000 + Math.random() * 900000).toString();

// --- AUTH MIDDLEWARES ---
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "No Token" });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user;
        next();
    });
};

const authorize = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "Access Denied" });
    next();
};
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(401).json({ error: "User not found" });

    const valid = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: "Wrong password" });

    const token = jwt.sign({ id: user.rows[0].id, role: user.rows[0].role,student_id: user.rows[0].student_id }, JWT_SECRET);
    res.json({ token, role: user.rows[0].role });
});
// ==========================================
// 1. DEPARTMENT CRUD
// ==========================================
app.post('/api/admin/depts', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, code } = req.body;
    const result = await pool.query('INSERT INTO departments (dept_name, dept_code) VALUES ($1, $2) RETURNING *', [name, code]);
    res.status(201).json(result.rows[0]);
});

app.get('/api/admin/depts', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT * FROM departments');
    res.json(result.rows);
});

app.put('/api/admin/depts/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, code } = req.body;
    await pool.query('UPDATE departments SET dept_name = $1, dept_code = $2 WHERE id = $3', [name, code, req.params.id]);
    res.json({ message: "Department Updated" });
});

app.delete('/api/admin/depts/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM departments WHERE id = $1', [req.params.id]);
    res.json({ message: "Department Deleted" });
});

// ==========================================
// 2. BATCH CRUD
// ==========================================
app.post('/api/admin/batches', authenticateToken, authorize(['admin']), async (req, res) => {
    const { dept_id, start_year, end_year, batch_name } = req.body;
    const result = await pool.query('INSERT INTO batches (dept_id, start_year, end_year, batch_name) VALUES ($1,$2,$3,$4) RETURNING *', [dept_id, start_year, end_year, batch_name]);
    res.json(result.rows[0]);
});

app.get('/api/admin/batches', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT b.*, d.dept_code FROM batches b JOIN departments d ON b.dept_id = d.id');
    res.json(result.rows);
});

app.put('/api/admin/batches/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { start_year, end_year, batch_name } = req.body;
    await pool.query('UPDATE batches SET start_year=$1, end_year=$2, batch_name=$3 WHERE id=$4', [start_year, end_year, batch_name, req.params.id]);
    res.json({ message: "Batch Updated" });
});

app.delete('/api/admin/batches/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM batches WHERE id = $1', [req.params.id]);
    res.json({ message: "Batch Deleted" });
});

// ==========================================
// 3. SECTION CRUD
// ==========================================
app.post('/api/admin/sections', authenticateToken, authorize(['admin']), async (req, res) => {
    const { batch_id, section_name } = req.body;
    const result = await pool.query('INSERT INTO sections (batch_id, section_name) VALUES ($1, $2) RETURNING *', [batch_id, section_name]);
    res.json(result.rows[0]);
});

app.get('/api/admin/sections', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT s.*, b.batch_name FROM sections s JOIN batches b ON s.batch_id = b.id');
    res.json(result.rows);
});

app.put('/api/admin/sections/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { section_name } = req.body;
    await pool.query('UPDATE sections SET section_name = $1 WHERE id = $2', [section_name, req.params.id]);
    res.json({ message: "Section Updated" });
});

app.delete('/api/admin/sections/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM sections WHERE id = $1', [req.params.id]);
    res.json({ message: "Section Deleted" });
});

// ==========================================
// 4. FACULTY CRUD
// ==========================================
app.post('/api/admin/faculty', authenticateToken, authorize(['admin']), async (req, res) => {
    const { email, password, name, dept_id, auth_key } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const hash = await bcrypt.hash(password, 10);
        const user = await client.query('INSERT INTO users (email, password_hash, role) VALUES ($1,$2,\'faculty\') RETURNING id', [email, hash]);
        await client.query('INSERT INTO faculty_profiles (user_id, faculty_name, dept_id, authorization_key) VALUES ($1,$2,$3,$4)', [user.rows[0].id, name, dept_id, auth_key]);
        await client.query('COMMIT');
        res.json({ message: "Faculty Created" });
    } catch (e) { await client.query('ROLLBACK'); res.status(500).json({ error: e.message }); } finally { client.release(); }
});

app.get('/api/admin/faculty', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT u.id, f.faculty_name, u.email, d.dept_code, f.authorization_key FROM users u JOIN faculty_profiles f ON u.id = f.user_id JOIN departments d ON f.dept_id = d.id WHERE u.role = \'faculty\'');
    res.json(result.rows);
});

app.put('/api/admin/faculty/:userId', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, auth_key, dept_id } = req.body;
    await pool.query('UPDATE faculty_profiles SET faculty_name=$1, authorization_key=$2, dept_id=$3 WHERE user_id=$4', [name, auth_key, dept_id, req.params.userId]);
    res.json({ message: "Faculty Profile Updated" });
});

app.delete('/api/admin/faculty/:userId', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM users WHERE id = $1 AND role = \'faculty\'', [req.params.userId]);
    res.json({ message: "Faculty Deleted" });
});

// ==========================================
// 5. STUDENT CRUD & CR PROMOTION
// ==========================================
app.post('/api/admin/students', authenticateToken, authorize(['admin']), async (req, res) => {
    const { roll, name, email, section_id } = req.body;
    await pool.query('INSERT INTO students (roll_number, full_name, email, section_id) VALUES ($1,$2,$3,$4)', [roll, name, email, section_id]);
    res.json({ message: "Student Added" });
});

app.get('/api/admin/students', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT s.*, sec.section_name FROM students s JOIN sections sec ON s.section_id = sec.id');
    res.json(result.rows);
});

app.put('/api/admin/students/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, roll, email, section_id } = req.body;
    await pool.query('UPDATE students SET full_name=$1, roll_number=$2, email=$3, section_id=$4 WHERE id=$5', [name, roll, email, section_id, req.params.id]);
    res.json({ message: "Student Updated" });
});

app.delete('/api/admin/students/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM students WHERE id = $1', [req.params.id]);
    res.json({ message: "Student Deleted" });
});

app.post('/api/admin/promote-cr', authenticateToken, authorize(['admin']), async (req, res) => {
    const { student_id, password } = req.body;
    const student = await pool.query('SELECT email FROM students WHERE id = $1', [student_id]);
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password_hash, role, student_id) VALUES ($1,$2,\'cr\',$3)', [student.rows[0].email, hash, student_id]);
    res.json({ message: "Promoted to CR" });
});

// ==========================================
// 6. COURSE CRUD
// ==========================================
app.post('/api/admin/courses', authenticateToken, authorize(['admin']), async (req, res) => {
    const { code, name, credits, dept_id } = req.body;
    await pool.query('INSERT INTO courses (course_code, course_name, credits, dept_id) VALUES ($1,$2,$3,$4)', [code, name, credits, dept_id]);
    res.json({ message: "Course Created" });
});

app.get('/api/admin/courses', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT * FROM courses');
    res.json(result.rows);
});

app.put('/api/admin/courses/:code', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, credits } = req.body;
    await pool.query('UPDATE courses SET course_name=$1, credits=$2 WHERE course_code=$3', [name, credits, req.params.code]);
    res.json({ message: "Course Updated" });
});

app.delete('/api/admin/courses/:code', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM courses WHERE course_code = $1', [req.params.code]);
    res.json({ message: "Course Deleted" });
});

// ==========================================
// 7. TIMETABLE CRUD & VIEW
// ==========================================
app.post('/api/admin/timetable', authenticateToken, authorize(['admin']), async (req, res) => {
    const { section_id, semester, day, slot, course_code, faculty_id, room } = req.body;
    await pool.query('INSERT INTO timetable (section_id, semester, day, slot_number, course_code, faculty_user_id, room_info) VALUES ($1,$2,$3,$4,$5,$6,$7)', [section_id, semester, day, slot, course_code, faculty_id, room]);
    res.json({ message: "Slot Added" });
});

app.get('/api/common/timetable', authenticateToken, async (req, res) => {
    const { section_id, semester } = req.query;
    const sql = `SELECT t.*, c.course_name, f.faculty_name FROM timetable t 
                 JOIN courses c ON t.course_code = c.course_code 
                 JOIN faculty_profiles f ON t.faculty_user_id = f.user_id 
                 WHERE section_id = $1 AND semester = $2 ORDER BY day, slot_number`;
    const result = await pool.query(sql, [section_id, semester]);
    res.json(result.rows);
});

app.put('/api/admin/timetable/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { day, slot, course_code, faculty_id, room } = req.body;
    await pool.query('UPDATE timetable SET day=$1, slot_number=$2, course_code=$3, faculty_user_id=$4, room_info=$5 WHERE id=$6', [day, slot, course_code, faculty_id, room, req.params.id]);
    res.json({ message: "Slot Updated" });
});

app.delete('/api/admin/timetable/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM timetable WHERE id = $1', [req.params.id]);
    res.json({ message: "Slot Deleted" });
});


app.put('/api/faculty/regen-token', authenticateToken, authorize(['faculty']), async (req, res) => {
    const newToken = generate6DigitToken();
    await pool.query('UPDATE faculty_profiles SET authorization_key = $1 WHERE user_id = $2', [newToken, req.user.id]);
    res.json({ message: "New Token Generated", token: newToken });
});



// app.get('/api/cr/my-courses', authenticateToken, authorize(['cr']), async (req, res) => {
//     const sql = `
//         SELECT DISTINCT c.* FROM courses c
//         JOIN departments d ON c.dept_id = d.id
//         JOIN batches b ON b.dept_id = d.id
//         JOIN sections s ON s.batch_id = b.id
//         JOIN students stu ON stu.section_id = s.id
//         WHERE stu.id = $1`;
//     const result = await pool.query(sql, [req.user.student_id]);
//     res.json(result.rows);
// });
app.get('/api/cr/my-courses', authenticateToken, authorize(['cr']), async (req, res) => {
    const sql = `
        SELECT DISTINCT c.*
        FROM courses c
        JOIN timetable t ON c.course_code = t.course_code
        JOIN students s ON t.section_id = s.section_id
        WHERE s.id = $1
        ORDER BY c.course_name ASC`;
    try {
        console.log(req.user.student_id);
        const result = await pool.query(sql, [req.user.student_id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/cr/attendance', authenticateToken, authorize(['cr']), async (req, res) => {
    const { timetable_id, date, records, selected_course_code, is_free } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Get Scheduled Course
        const tt = await client.query('SELECT course_code FROM timetable WHERE id = $1', [timetable_id]);
        const scheduledCourse = tt.rows[0].course_code;

        let category = 'normal';
        if (is_free) category = 'free';
        else if (selected_course_code !== scheduledCourse) category = 'swap';

        // 2. Create Session
        const sessSql = `
            INSERT INTO attendance_sessions 
            (timetable_id, session_date, marked_by_user_id, session_category, actual_course_code) 
            VALUES ($1, $2, $3, $4, $5) RETURNING id`;
        const sessRes = await client.query(sessSql, [timetable_id, date, req.user.id, category, selected_course_code]);
        const sessionId = sessRes.rows[0].id;

        // 3. Insert Records (Skip if free)
        if (category !== 'free') {
            for (let r of records) {
                await client.query('INSERT INTO attendance_records (session_id, student_id, status) VALUES ($1, $2, $3)', 
                [sessionId, r.id, r.status]);
            }
        }

        await client.query('COMMIT');
        res.json({ message: "Attendance processed", sessionId, category });
    } catch (e) { await client.query('ROLLBACK'); res.status(500).json({ error: e.message }); } finally { client.release(); }
});


app.get('/api/common/week-grid', authenticateToken, async (req, res) => {
    const { section_id, start_date } = req.query; 
    const sql = `
        SELECT t.*, c.course_name, f.faculty_name, sess.session_category, sess.id as session_id
        FROM timetable t
        JOIN courses c ON t.course_code = c.course_code
        JOIN faculty_profiles f ON t.faculty_user_id = f.user_id
        LEFT JOIN attendance_sessions sess ON sess.timetable_id = t.id 
             AND sess.session_date = ($2::date + (CASE t.day 
                WHEN 'Mon' THEN 0 WHEN 'Tue' THEN 1 WHEN 'Wed' THEN 2 WHEN 'Thu' THEN 3 WHEN 'Fri' THEN 4 ELSE 0 END))
        WHERE t.section_id = $1`;
    const result = await pool.query(sql, [section_id, start_date]);
    res.json(result.rows);
});


app.get('/api/common/timetable-by-class', authenticateToken, async (req, res) => {
    const { dept_code, section_name, semester } = req.query; // ?dept_code=CSE&section_name=A&semester=5
    const sql = `
        SELECT t.*, c.course_name, f.faculty_name 
        FROM timetable t
        JOIN sections s ON t.section_id = s.id
        JOIN batches b ON s.batch_id = b.id
        JOIN departments d ON b.dept_id = d.id
        JOIN courses c ON t.course_code = c.course_code
        JOIN faculty_profiles f ON t.faculty_user_id = f.user_id
        WHERE d.dept_code = $1 AND s.section_name = $2 AND t.semester = $3
        ORDER BY t.day, t.slot_number`;
    const result = await pool.query(sql, [dept_code, section_name, semester]);
    res.json(result.rows);
});

// Get all attendance sessions for a specific timetable slot (Admin View)
app.get('/api/admin/sessions-by-timetable/:ttId', authenticateToken, authorize(['admin']), async (req, res) => {
    try {
        const sql = `
            SELECT sess.id, sess.session_date, sess.is_verified_by_faculty, u.email as marked_by
            FROM attendance_sessions sess
            JOIN users u ON sess.marked_by_user_id = u.id
            WHERE sess.timetable_id = $1
            ORDER BY sess.session_date DESC`;
        const result = await pool.query(sql, [req.params.ttId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get detailed student records for a specific session ID
app.get('/api/admin/records-by-session/:sessionId', authenticateToken, authorize(['admin']), async (req, res) => {
    try {
        const sql = `
            SELECT s.roll_number, s.full_name, r.status
            FROM attendance_records r
            JOIN students s ON r.student_id = s.id
            WHERE r.session_id = $1
            ORDER BY s.roll_number ASC`;
        const result = await pool.query(sql, [req.params.sessionId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// Get students for a specific timetable slot
app.get('/api/cr/students-by-timetable/:ttId', authenticateToken, authorize(['cr', 'admin']), async (req, res) => {
    try {
        const sql = `
            SELECT s.* 
            FROM students s 
            JOIN timetable t ON s.section_id = t.section_id 
            WHERE t.id = $1
            ORDER BY s.roll_number ASC`;
        const result = await pool.query(sql, [req.params.ttId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/faculty/verify/:sessionId', authenticateToken, authorize(['faculty']), async (req, res) => {
    const { token } = req.body;
    const profile = await pool.query('SELECT authorization_key FROM faculty_profiles WHERE user_id = $1', [req.user.id]);
    if (profile.rows[0].authorization_key !== token) return res.status(401).json({ error: "Invalid 6-digit Token" });
    
    await pool.query('UPDATE attendance_sessions SET is_verified_by_faculty = true, verified_at = NOW() WHERE id = $1', [req.params.sessionId]);
    res.json({ message: "Attendance verified and locked" });
});

app.listen(3000, () => console.log("Server Running on 3000"));