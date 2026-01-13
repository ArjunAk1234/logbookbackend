-- 1. Departments & Batches
CREATE TABLE departments (
    id SERIAL PRIMARY KEY,
    dept_name VARCHAR(100) NOT NULL,
    dept_code VARCHAR(10) UNIQUE NOT NULL 
);

CREATE TABLE batches (
    id SERIAL PRIMARY KEY,
    dept_id INTEGER NOT NULL REFERENCES departments(id),
    start_year INTEGER NOT NULL,
    end_year INTEGER NOT NULL,
    batch_name VARCHAR(100) NOT NULL
);

-- 2. Sections (e.g., AIE-A, AIE-B)
CREATE TABLE sections (
    id SERIAL PRIMARY KEY,
    batch_id INTEGER NOT NULL REFERENCES batches(id),
    section_name VARCHAR(10) NOT NULL,
    UNIQUE (batch_id, section_name)
);

-- 3. Students Table (Master list added by Admin)
CREATE TABLE students (
    id SERIAL PRIMARY KEY,
    roll_number VARCHAR(30) UNIQUE NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL, -- am.sc.u4aie23019@am.students.edu
    section_id INTEGER NOT NULL REFERENCES sections(id),
    is_active BOOLEAN DEFAULT true
);

-- 4. Login Users (Admin, Faculty, CR)
CREATE TYPE user_role AS ENUM ('admin', 'faculty', 'cr');

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role NOT NULL,
    -- If CR, link to their student record
    student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. Faculty Profiles (Specific info for teachers)
CREATE TABLE faculty_profiles (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    faculty_name VARCHAR(150) NOT NULL,
    dept_id INTEGER REFERENCES departments(id),
    -- Secret key used to verify attendance marking
    authorization_key VARCHAR(50) NOT NULL, 
    designation VARCHAR(100)
);

-- 6. Courses & Timetable
CREATE TABLE courses (
    course_code VARCHAR(20) PRIMARY KEY,
    course_name VARCHAR(150) NOT NULL,
    credits INTEGER NOT NULL,
    dept_id INTEGER REFERENCES departments(id)
);

CREATE TYPE day_of_week AS ENUM ('Mon', 'Tue', 'Wed', 'Thu', 'Fri');

CREATE TABLE timetable (
    id SERIAL PRIMARY KEY,
    section_id INTEGER NOT NULL REFERENCES sections(id),
    semester INTEGER NOT NULL,
    day day_of_week NOT NULL,
    slot_number INTEGER NOT NULL CHECK (slot_number BETWEEN 1 AND 9),
    course_code VARCHAR(20) REFERENCES courses(course_code),
    faculty_user_id INTEGER REFERENCES users(id), -- Points to a 'faculty' role user
    room_info VARCHAR(100), -- e.g., 'N209D', 'Lab S304B'
    UNIQUE (section_id, semester, day, slot_number)
);

-- 7. Attendance Logic
CREATE TABLE attendance_sessions (
    id SERIAL PRIMARY KEY,
    timetable_id INTEGER NOT NULL REFERENCES timetable(id),
    session_date DATE NOT NULL,
    marked_by_user_id INTEGER NOT NULL REFERENCES users(id), -- The CR who logged in
    -- Verified becomes true when Faculty enters their authorization_key
    is_verified_by_faculty BOOLEAN DEFAULT false,
    verified_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'scheduled', -- 'scheduled', 'completed', 'cancelled'
    UNIQUE (timetable_id, session_date)
);

CREATE TABLE attendance_records (
    id SERIAL PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES attendance_sessions(id) ON DELETE CASCADE,
    student_id INTEGER NOT NULL REFERENCES students(id),
    status VARCHAR(10) NOT NULL CHECK (status IN ('present', 'absent', 'late')),
    UNIQUE (session_id, student_id)
);

-- 8. Swap Management
CREATE TABLE class_swaps (
    id SERIAL PRIMARY KEY,
    -- The original timetable slot being swapped
    source_timetable_id INTEGER NOT NULL REFERENCES timetable(id),
    requesting_faculty_id INTEGER NOT NULL REFERENCES users(id),
    target_faculty_id INTEGER REFERENCES users(id), -- Faculty taking the class
    
    requested_date DATE NOT NULL,
    reason TEXT,
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'approved', 'rejected'
    
    -- Admin or Target Faculty approval
    approved_by_id INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE faculty_profiles 
ADD COLUMN email VARCHAR(150) UNIQUE NOT NULL;

INSERT INTO users (email, password_hash, role) 
VALUES (
    'admin@system.com', 
    '$2b$10$QNMYt2VhJjvwOqIIYeosHeXs1.Xzu65fI/I1N70g16rdylDekQDy2', 
    'admin'
);

"password"

select * from users;
select * from students;
select  * from batches;
select * from faculty_profiles;
select * from attendance_sessions;
select * from attendance_records ;
update  users set student_id='1' where email='sudent@system.com';