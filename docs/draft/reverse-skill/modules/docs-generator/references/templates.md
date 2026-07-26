# 문서 템플릿

## 목차

- [README.md](#readmemd)
- [API 엔드포인트 문서](#api-엔드포인트-문서)
- [파일 시스템 구성](#파일-시스템-구성)

## README.md

```markdown
# Project Name

One-line description of what this does.

## Quick Start

\`\`\`bash
yarn install && yarn dev
\`\`\`

## Installation

Step-by-step setup.

## Usage

\`\`\`typescript
import { thing } from "package";
const result = thing.doSomething();
\`\`\`

## Configuration

| Variable  | Required | Default | Description  |
| --------- | -------- | ------- | ------------ |
| `API_KEY` | Yes      | -       | Your API key |

## Documentation

- [API Reference](./docs/api/README.md)
- [Architecture](./docs/architecture/overview.md)
```

## API 엔드포인트 문서

```markdown
# Resource Name

Brief description.

## GET /resource

Retrieves resources.

**Parameters**

| Name    | Type   | Required | Description               |
| ------- | ------ | -------- | ------------------------- |
| `limit` | number | No       | Max results (default: 20) |

**Response**

\`\`\`json
{
  "data": [],
  "total": 100
}
\`\`\`

**Example**

\`\`\`typescript
const { data } = await api.get("/resource", { limit: 10 });
\`\`\`

**Errors**

| Status | Code             | Description              |
| ------ | ---------------- | ------------------------ |
| 400    | `INVALID_PARAMS` | Invalid query parameters |
| 401    | `UNAUTHORIZED`   | Missing or invalid auth  |
```

## 파일 시스템 구성

```text
/docs
├── README.md              # Docs index
├── /api
│   ├── README.md          # API overview
│   ├── authentication.md
│   └── {resource}.md
├── /architecture
│   ├── overview.md
│   └── data-flow.md
├── /guides
│   ├── getting-started.md
│   └── troubleshooting.md
└── /features
    └── {NNN}-{feature}.md
```
