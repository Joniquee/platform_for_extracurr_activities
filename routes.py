from flask import Blueprint
from models import db, User  # ����������� �� models

bp = Blueprint('main', __name__)

@bp.route('/')
def home():
    return "������� ��������"