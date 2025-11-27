from app import Session
from models import User
db = Session()
u = User(username="admin", email="srms1161@gmail.com")
u.set_password("admin1234@")
u.is_admin = True
db.add(u); db.commit(); db.close()
