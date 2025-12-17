from flask import Flask , render_template
from controller.config import Config
from controller.database import db
from controller.models import *

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()

@app.route("/")
def hello_world():
    return render_template("Quiz_Master.html")

if __name__ == "__main__":
    app.run()