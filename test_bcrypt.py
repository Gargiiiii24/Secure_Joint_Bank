import bcrypt

password = "Test@123"

hashed = bcrypt.hashpw(
    password.encode("utf-8"),
    bcrypt.gensalt()
)

print("Original password:", password)
print("Hashed password:", hashed.decode("utf-8"))

if bcrypt.checkpw(password.encode("utf-8"), hashed):
    print("Password verification: SUCCESS")
else:
    print("Password verification: FAILED")