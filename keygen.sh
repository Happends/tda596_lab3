openssl req -x509 -newkey rsa:4096 -days 365 -keyout ca.key -out ca.crt -config ./openssl.cnf -nodes -extensions v3_ca

openssl req -newkey rsa:4096 -keyout server.key -out server.csr -config ./openssl.cnf -nodes -extensions v3_req

openssl req -newkey rsa:4096 -keyout client.key -out client.csr -config ./openssl.cnf -nodes -extensions v3_req

openssl x509 -in ca.crt -noout -text

openssl x509 -req -in server.csr -days 60 -CA ca.crt -CAkey ca.key -CAcreateserial -out server_signed.crt -extfile ./openssl.cnf -extensions v3_req

openssl x509 -req -in client.csr -days 60 -CA ca.crt -CAkey ca.key -CAcreateserial -out client_signed.crt -extfile ./openssl.cnf -extensions v3_req

openssl x509 -in server_signed.crt -noout -text
openssl x509 -in client_signed.crt -noout -text