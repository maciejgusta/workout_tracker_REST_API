FROM python:3.13-slim

WORKDIR /code

COPY requirements.txt ./

RUN pip install -r requirements.txt

COPY . . 

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
