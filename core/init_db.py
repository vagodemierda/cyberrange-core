from core.db import engine, Base
from core import models  # noqa: F401 (importa modelos)

def init():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init()
    print("DB inicializada.")
