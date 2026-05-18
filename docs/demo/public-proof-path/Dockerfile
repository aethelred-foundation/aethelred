FROM node:20-alpine

WORKDIR /app

COPY package.json ./
COPY src ./src

RUN mkdir -p /data && chown -R node:node /app /data

ENV AETHELRED_PROOF_HOST=0.0.0.0
ENV AETHELRED_PROOF_PORT=8088
ENV AETHELRED_PROOF_OUTPUT_DIR=/data
ENV AETHELRED_AUTO_RUN=1

EXPOSE 8088

USER node

CMD ["node", "src/server.mjs"]
