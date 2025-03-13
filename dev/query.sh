#!/bin/bash

TOKEN=$1

curl --insecure https://localhost/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{
  "model": "qwen:0.5b",
  "messages": [
    {
      "role": "user", 
      "content": "why is the sky blue?"
    }
  ]
}'

curl --insecure https://localhost/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{
  "model": "qwen:0.5b",
  "stream": true,
  "messages": [
    {
      "role": "user", 
      "content": "why is the sky blue?"
    }
  ]
}'
