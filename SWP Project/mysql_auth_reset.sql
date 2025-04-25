UPDATE mysql.user SET plugin='mysql_native_password' WHERE User='root';
UPDATE mysql.user SET authentication_string=PASSWORD('Mokgaga.082') WHERE User='root';
FLUSH PRIVILEGES;
