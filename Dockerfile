# KavachForge - portable, self-contained image.
# Ships the full LLVM/clang libFuzzer + AddressSanitizer toolchain so the
# premium coverage-guided discovery engine works identically on any machine
# (Linux, macOS, Windows) that can run Docker.
FROM python:3.12-slim

# clang + compiler-rt (libFuzzer & sanitizer runtimes), patch, git.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libclang-rt-dev patch git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# No pip dependencies: KavachForge is standard-library only.
ENV PYTHONUNBUFFERED=1

# Let the engine auto-detect; clang libFuzzer is available in this image.
ENTRYPOINT ["python3", "-m", "kavachforge"]
CMD ["demo"]
