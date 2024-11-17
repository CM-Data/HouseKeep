from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy


#db = SQLAlchemy(app)
#migrate = Migrate(app, db)

login_managerr = LoginManager()
login_managerr.init_app(app)
login_managerr.login_view = 'login'