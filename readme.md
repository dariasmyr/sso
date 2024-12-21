# SSO
The SSO is an open-source microservice for managing users and authentication across multiple apps. It supports token-based authentication (JWT) and integrates with a variety of back-end storage systems.

![SSO Architecture](docs/architecture.png "SSO Microservice Architecture")

## SSO Flow Diagram

![SSO Flow](docs/flow.svg "SSO Flow")

## Getting Started

### Setup
Clone the repository:

```bash
git clone https://github.com/dariasmyr/sso.git
cd sso-microservice
```

## Configuration
Configuration files are located in `./config/`. Modify `config_local.yaml` for local setups and `config_prod.yaml` for production.

## Install dependencies:

```bash
make tidy
```

## Build and Run
Build the service:

```bash
make build
```

Run the service (!Check the configuration file!):

```bash
make execute
```

## Run database migrations:

```bash
make migrations-run
```


## Test the service:
```bash
make test
```


## Docker
Build and run with Docker Compose:
```bash
# Launch
$ docker-compose up -d

# Rebuild and launch
$ docker-compose up -d --build

# Stop
Stop the service (default port: 55055):
$ docker-compose down
```

License
MIT License. See LICENSE for details.


