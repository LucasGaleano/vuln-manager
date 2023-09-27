FROM python:latest


WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt



CMD ["python","-u","./manager.py"]



#docker run -d --rm -p 127.0.0.1:27017:27017 --network vuln-network -v mongodb-vuln:/data/db --name mongo mongo
#docker run -d --rm -p 127.0.0.1:27017:27017  --network vuln-network --name mongo mongo 
#docker network create vuln-network
#docker build -t vuln_management .
#docker run -d --rm  --log-driver syslog --log-opt tag="{{.Name}}" --network vuln-network --name vuln_management vuln_management