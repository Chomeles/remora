FROM python:3.12-alpine
COPY shears.py /app/shears.py
ENV MCADMIN_DATA=/data
VOLUME /data
EXPOSE 8080
CMD ["python3", "/app/shears.py"]
