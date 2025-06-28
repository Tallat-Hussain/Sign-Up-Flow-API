from fastapi import FastAPI
#from .. import models, database, schemas
import models
import database
import schemas
from routers import auth
import oauth2


app = FastAPI()

models.Base.metadata.create_all(bind=database.engine)

app.include_router(auth.router)