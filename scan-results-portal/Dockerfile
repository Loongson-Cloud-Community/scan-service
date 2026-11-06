FROM lcr.loongnix.cn/loongnix-server/loongnix-server:23.3
RUN sed -i '/\[updates\]/,/enabled=/ s/enabled=1/enabled=0/' /etc/yum.repos.d/Loongnix-Server.repo
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN dnf --disablerepo=updates install -y libpq && \
    dnf clean all && \
    rm -rf /var/cache/dnf

COPY requirements.txt .
RUN python3 -m ensurepip --upgrade && \
    python3 -m pip install --no-cache-dir setuptools wheel && \
    python3 -m pip install --no-cache-dir --no-build-isolation -r requirements.txt

COPY alembic.ini .
COPY migrations ./migrations
COPY app/scanservice ./scanservice
COPY tests ./tests

EXPOSE 8080

CMD ["sh", "-c", "alembic upgrade head && exec uvicorn scanservice.main:app --host 0.0.0.0 --port 8080"]
