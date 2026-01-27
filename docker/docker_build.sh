docker compose down
cd ..
docker build -t api-server:latest -f docker/Dockerfile .
cd docker
docker compose up -d