#!/bin/bash

# Script to export existing PostgreSQL container as Docker image
# This preserves all your vulnerability data

set -e

# Configuration
CONTAINER_NAME="vuln_db_postgres"  # Your actual container name
IMAGE_NAME="vuln-db-with-data"
IMAGE_TAG="latest"
DOCKERHUB_USERNAME="yadavanup84"  # Docker Hub username

echo "🚀 Exporting PostgreSQL container as Docker image..."

# Check if container exists and is running
if ! docker ps -a --format 'table {{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "❌ Container '${CONTAINER_NAME}' not found!"
    echo "Available containers:"
    docker ps -a --format 'table {{.Names}}\t{{.Status}}'
    exit 1
fi

echo "✅ Found container: ${CONTAINER_NAME}"

# Check container status
CONTAINER_STATUS=$(docker inspect -f '{{.State.Status}}' ${CONTAINER_NAME})
echo "📊 Container status: ${CONTAINER_STATUS}"

if [ "${CONTAINER_STATUS}" != "running" ]; then
    echo "⚠️ Container is not running. Starting it..."
    docker start ${CONTAINER_NAME}
    sleep 10
fi

# Get database stats before export
echo "📈 Getting database statistics..."
docker exec ${CONTAINER_NAME} psql -U vuln_user -d vulnerability_db -c "
SELECT 
    'cves' as table_name, 
    COUNT(*) as record_count 
FROM cves
UNION ALL
SELECT 
    'cpe_matches' as table_name, 
    COUNT(*) as record_count 
FROM cpe_matches
UNION ALL
SELECT 
    'mitre_techniques' as table_name, 
    COUNT(*) as record_count 
FROM mitre_techniques;
"

# Commit the container as a new image
echo "💾 Committing container as Docker image..."
docker commit \
    --author "Vulnerability Engine Team" \
    --message "PostgreSQL database with pre-loaded vulnerability data from NVD and other sources" \
    ${CONTAINER_NAME} \
    ${IMAGE_NAME}:${IMAGE_TAG}

echo "✅ Successfully created image: ${IMAGE_NAME}:${IMAGE_TAG}"

# Show image details
echo "📋 Image details:"
docker images ${IMAGE_NAME}:${IMAGE_TAG}

# Tag for Docker Hub (update with your username)
echo "🏷️ Tagging image for Docker Hub..."
docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${DOCKERHUB_USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}

echo "✅ Image tagged as: ${DOCKERHUB_USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}"

# Test the new image
echo "🧪 Testing the new image..."
docker run --rm -d \
    --name test-${IMAGE_NAME} \
    -e POSTGRES_DB=vulnerability_db \
    -e POSTGRES_USER=vuln_user \
    -e POSTGRES_PASSWORD=vuln_pass \
    -p 5433:5432 \
    ${IMAGE_NAME}:${IMAGE_TAG}

# Wait for database to start
echo "⏳ Waiting for database to start..."
sleep 15

# Test database connection and data
echo "🔍 Testing database connection and data..."
docker exec test-${IMAGE_NAME} psql -U vuln_user -d vulnerability_db -c "
SELECT 
    'cves' as table_name, 
    COUNT(*) as record_count,
    MAX(published_date) as latest_cve_date
FROM cves;
"

# Clean up test container
echo "🧹 Cleaning up test container..."
docker stop test-${IMAGE_NAME}

echo ""
echo "🎉 SUCCESS! Your database image is ready!"
echo ""
echo "📦 Image details:"
echo "   Local image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "   Docker Hub: ${DOCKERHUB_USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "🚀 Next steps:"
echo "   1. Login to Docker Hub: docker login"
echo "   2. Push image: docker push ${DOCKERHUB_USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}"
echo "   3. Share with partner: docker pull ${DOCKERHUB_USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "💡 Your partner can use it with:"
echo "   docker run -d --name vuln-db -p 5432:5432 ${DOCKERHUB_USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}"
