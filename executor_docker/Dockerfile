FROM python:3.11-alpine

ENV EXECUTOR_PORT=5000
EXPOSE 5000
WORKDIR /root

RUN pip install "fastapi[standard]"
RUN python -m venv venv
COPY code_template.py server.py ./
CMD ["python", "server.py"]
