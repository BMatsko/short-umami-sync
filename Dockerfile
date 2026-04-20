FROM golang:1.22-alpine AS build
WORKDIR /app
ENV GONOSUMDB=* GOFLAGS=-mod=mod
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o short-umami-sync .

FROM alpine:3.21
WORKDIR /app
COPY --from=build /app/short-umami-sync .
EXPOSE 8080
CMD ["/app/short-umami-sync"]
