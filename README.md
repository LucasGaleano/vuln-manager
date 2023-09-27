# openvas-client
Automated openvas scan via API



# Install 

```
docker network create vuln-network
docker run -d --rm -p 127.0.0.1:27017:27017 --network vuln-network -v mongodb-vuln:/data/db -e MONGO_INITDB_ROOT_USERNAME=mongoadmin -e MONGO_INITDB_ROOT_PASSWORD=secret --name mongo mongo
docker build -t vuln_management .
docker run -d --rm  --log-driver syslog --log-opt tag="{{.Name}}" --network vuln-network --name vuln_management vuln_management
```