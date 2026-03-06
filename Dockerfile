FROM --platform=$BUILDPLATFORM golang:1.25 AS builder

ARG TARGETOS TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o webhook .

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /app/webhook /webhook

USER nonroot:nonroot

ENTRYPOINT ["/webhook"]
