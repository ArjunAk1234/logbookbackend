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


CREATE TYPE user_role AS ENUM ('admin', 'faculty', 'cr','student');

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role NOT NULL,
    
    student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE courses (
    course_code VARCHAR(20) PRIMARY KEY,
    course_name VARCHAR(150) NOT NULL,
    credits INTEGER NOT NULL,
    dept_id INTEGER REFERENCES departments(id)
);

CREATE TYPE day_of_week AS ENUM ('Mon', 'Tue', 'Wed', 'Thu', 'Fri');
CREATE TABLE faculty_profiles (
    id SERIAL PRIMARY KEY, 
    user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE SET NULL, 
    faculty_name VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL,
    dept_id INTEGER REFERENCES departments(id),
    authorization_key VARCHAR(50) NOT NULL, 
    designation VARCHAR(100)
);


CREATE TABLE timetable (
    id SERIAL PRIMARY KEY,
    section_id INTEGER NOT NULL REFERENCES sections(id),
    semester INTEGER NOT NULL,
    day VARCHAR(10) NOT NULL, 
    slot_number INTEGER NOT NULL CHECK (slot_number BETWEEN 1 AND 9),
    course_code VARCHAR(20) REFERENCES courses(course_code),
    faculty_profile_id INTEGER REFERENCES faculty_profiles(id), e
    room_info VARCHAR(100),
    UNIQUE (section_id, semester, day, slot_number)
);

CREATE TABLE attendance_sessions (
    id SERIAL PRIMARY KEY,
    timetable_id INTEGER REFERENCES timetable(id),
    session_date DATE NOT NULL,
    marked_by_user_id INTEGER REFERENCES users(id),
    session_category VARCHAR(20) DEFAULT 'normal',
    actual_course_code VARCHAR(20),
    is_verified_by_faculty BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS class_swaps (
    id SERIAL PRIMARY KEY,
    source_timetable_id INTEGER NOT NULL REFERENCES timetable(id),
    requesting_faculty_id INTEGER NOT NULL REFERENCES faculty_profiles(id), 
    target_faculty_id INTEGER REFERENCES faculty_profiles(id),
    requested_date DATE NOT NULL,
    reason TEXT,
    status VARCHAR(20) DEFAULT 'approved', 
    approved_by_id INTEGER REFERENCES faculty_profiles(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);




CREATE TABLE attendance_records (
    id SERIAL PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES attendance_sessions(id) ON DELETE CASCADE,
    student_id INTEGER NOT NULL REFERENCES students(id),
    status VARCHAR(10) NOT NULL CHECK (status IN ('present', 'absent', 'late')),
    UNIQUE (session_id, student_id)
);



ALTER TABLE users ADD COLUMN semester INTEGER;

TRUNCATE TABLE
    attendance_records,
    attendance_sessions,
    class_swaps,
    timetable,
    faculty_profiles,
    users,
    students,
    sections,
    batches,
    departments,
    courses
RESTART IDENTITY CASCADE;



INSERT INTO users (email, password_hash, role) 
VALUES (
    'admin@system.com', 
    '$2b$10$QNMYt2VhJjvwOqIIYeosHeXs1.Xzu65fI/I1N70g16rdylDekQDy2', 
    'admin'
);
