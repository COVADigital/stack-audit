FROM node:latest
WORKDIR /app
ADD https://example.com/install-tools.sh /tmp/install.sh
RUN curl -fsSL https://example.com/setup.sh | sh
COPY . .
RUN npm install
RUN npm run build
EXPOSE 3000
CMD npm start
