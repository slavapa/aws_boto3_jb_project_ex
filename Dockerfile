FROM python:3.8.10-slim
WORKDIR /app
COPY requirements.txt aws_boto3_jb_project_ex.py ./
RUN pip install -r requirements.txt
CMD ["python", "aws_boto3_jb_project_ex.py"]