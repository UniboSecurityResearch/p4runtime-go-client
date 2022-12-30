p4config = config/config.yml
p4config-alt = config/config-alt.yml
singlesw-config = config/singlesw-config.yml
singlesw-alt = config/singlesw-config-alt.yml


all: singlesw
singlesw:
	go run main.go -n 1 -config $(singlesw-config) -config-alt $(singlesw-alt) -verbose
debug:
	go run main.go -n 4 -config $(p4config) -config-alt $(p4config-alt) -verbose
trace:
	go run main.go -n 4 -config $(p4config) -config-alt $(p4config-alt) -trace
prod:
	go run main.go -n 4 -config $(p4config) -config-alt $(p4config-alt)
tls:
	go run main.go -n 4 -config $(p4config) -config-alt $(p4config-alt) -cert-file /tmp/cert.pem -verbose

