FROM python:latest


WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt



CMD ["python","-u","./openvas.py"]



#docker run -d --rm -p 127.0.0.1:27017:27017 --network vuln-network -v mongodb-vuln:/data/db --name mongo mongo:4.4.23  
#docker build -t vuln_management .
#docker run --rm  --log-driver syslog --log-opt tag="{{.Name}}" --network vuln-network --name vuln_management vuln_management