-- Insert admin user into admin_db.admins
INSERT INTO admins (email, password, created_at) VALUES (
  'tebogo@gmail.com',
  '$2b$12$OlaRieoYo45aGz.EQihU6eKOFlbFc0KSW5.3kbarvukvJa1c8a1EG', -- bcrypt hash of "tebogo"
  NOW()
);

-- Insert law enforcement officer into police_db.officers
INSERT INTO officers (email, password, station, badge_number, created_at) VALUES (
  'setshaba@gmail.com',
  '$2b$12$7/tCOboMUDjeqqQrkUJ4NuQzJFciDLTghCnmLFU83jKrPhl0O7iga', -- bcrypt hash of "setshaba"
  'Johannesburg Central',
  'JHB1234',
  NOW()
);
