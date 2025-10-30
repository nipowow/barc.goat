from flask_bcrypt import Bcrypt

Bcrypt = Bcrypt()

password = "contraseña"
hashed_pw = Bcrypt.generate_password_hash(password).decode('utf-8')

stored_pw = hashed_pw

input_pw = "contraseña"

if Bcrypt.check_password_hash(stored_pw, input_pw):
   print("Login correcto")
else:
    print("Contraseña incorrecta") 