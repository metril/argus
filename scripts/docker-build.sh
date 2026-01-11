#!/bin/bash
# Multi-arch Docker build script for Adblocker Proxy
# Usage: ./scripts/docker-build.sh [OPTIONS]
#
# Options:
#   --push          Push to registry after build
#   --tag TAG       Image tag (default: latest)
#   --registry REG  Registry prefix (default: none)
#   --platform PLAT Platforms to build (default: linux/amd64,linux/arm64)
#   --no-cache      Build without cache

set -euo pipefail

# Default values
PUSH=false
TAG="latest"
REGISTRY=""
PLATFORMS="linux/amd64,linux/arm64"
NO_CACHE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --push)
            PUSH=true
            shift
            ;;
        --tag)
            TAG="$2"
            shift 2
            ;;
        --registry)
            REGISTRY="$2/"
            shift 2
            ;;
        --platform)
            PLATFORMS="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --push          Push to registry after build"
            echo "  --tag TAG       Image tag (default: latest)"
            echo "  --registry REG  Registry prefix (default: none)"
            echo "  --platform PLAT Platforms (default: linux/amd64,linux/arm64)"
            echo "  --no-cache      Build without cache"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

IMAGE_NAME="${REGISTRY}adblocker-proxy:${TAG}"

echo "Building multi-arch Docker image..."
echo "  Image: ${IMAGE_NAME}"
echo "  Platforms: ${PLATFORMS}"
echo "  Push: ${PUSH}"

# Ensure buildx is available
if ! docker buildx version &> /dev/null; then
    echo "Error: docker buildx is not available"
    echo "Install with: docker buildx install"
    exit 1
fi

# Create/use buildx builder for multi-arch
BUILDER_NAME="adblocker-multiarch"
if ! docker buildx inspect ${BUILDER_NAME} &> /dev/null; then
    echo "Creating buildx builder: ${BUILDER_NAME}"
    docker buildx create --name ${BUILDER_NAME} --driver docker-container --bootstrap
fi
docker buildx use ${BUILDER_NAME}

# Build command
BUILD_CMD="docker buildx build"
BUILD_CMD+=" --platform ${PLATFORMS}"
BUILD_CMD+=" -t ${IMAGE_NAME}"
BUILD_CMD+=" -f Dockerfile"
BUILD_CMD+=" ${NO_CACHE}"

if [[ "${PUSH}" == "true" ]]; then
    BUILD_CMD+=" --push"
else
    # Load single-arch for local use if not pushing
    if [[ "${PLATFORMS}" == *","* ]]; then
        echo "Note: Multi-arch builds require --push or single platform for local load"
        BUILD_CMD+=" --push"
    else
        BUILD_CMD+=" --load"
    fi
fi

BUILD_CMD+=" ."

echo ""
echo "Executing: ${BUILD_CMD}"
echo ""

${BUILD_CMD}

echo ""
echo "Build complete!"
if [[ "${PUSH}" == "true" ]]; then
    echo "Image pushed to: ${IMAGE_NAME}"
else
    echo "Image available locally: ${IMAGE_NAME}"
fi
