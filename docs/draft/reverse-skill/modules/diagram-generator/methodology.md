---
name: diagram-generator
description: 자연어, 메모, 코드 조각, 스키마, 테이블 또는 기존 다이어그램 소스에서 다이어그램을 생성, 구체화, 검증 및 렌더링합니다. 순서도, 스윔레인, 시퀀스 다이어그램, 상태 다이어그램, er 다이어그램, 클래스 다이어그램, architecture/c4-style 다이어그램, 종속성 그래프, 간트 차트, 마인드 맵, 사용자 여정, Sankey 스타일 흐름, 조직 차트, 네트워크 그래프 및 기타 시각적 모델에 사용됩니다. 기본적으로 mermaid, 복잡한 그래프 레이아웃을 위한 graphviz dot, uml이 많은 엔지니어링 다이어그램을 위한 plantuml, 직접 마크업이 더 안정적인 경우 svg 출력을 지원합니다.
---

# Diagram Generator

## Purpose

지저분하거나 구조화된 입력에서 명확하고 편집 가능한 다이어그램을 만듭니다. 결과를 검토하고 버전을 지정하고 구체화할 수 있도록 텍스트 기반 다이어그램 소스를 먼저 선호하세요. 사용자가 image/PDF를 요청하거나 다운로드 가능한 아티팩트가 실질적으로 도움이 될 때만 파일로 렌더링하세요.

## Default workflow

1. 사용자의 의도, 청중, 소스 자료를 식별합니다.
2. 아래 결정표를 사용하여 다이어그램 제품군과 언어를 선택하세요.
3. 다이어그램 코드를 작성하기 전에 엔터티, 관계, 레이블, 상태, 분기 및 time/order 정보를 정규화하세요.
4. 간결하고 읽기 쉬운 다이어그램 소스를 생성합니다.
5. 구문을 검토하고, 파일을 생성할 때는 설치된 공식 렌더러로 실제 렌더링을 확인하세요.
6. 소스 다이어그램과 가정에 대한 간단한 메모를 반환합니다. 파일이 생성되면 출력 파일에 대한 링크를 포함합니다.

설명을 과도하게 요청하지 마십시오. 요청이 과소 지정되면 합리적인 가정을 하고 간략하게 라벨을 지정하세요.

## 다이어그램 언어 결정 테이블

다른 언어가 확실히 더 나은 경우가 아니면 Mermaid를 사용하세요.

| User wants | Prefer | Why |
|---|---|---|
| 프로세스 흐름, 의사결정 트리, 단순 스윔레인 | Mermaid flowchart | 읽기 쉽고 Markdown에 붙여넣기 쉽습니다. |
| system/user 상호작용의 순서 | Mermaid 시퀀스 다이어그램 또는 PlantUML 시퀀스 | Mermaid 문서용; PlantUML UML 형식의 경우 |
| 수명주기, 상태 머신, 전환 | Mermaid stateDiagram-v2 또는 PlantUML 상태 | 컴팩트 전환 구문 |
| 데이터베이스 스키마, 엔터티, 관계 | Mermaid erDiagram | 휴대용 ER 표기법 |
| class/interface/object 모델 | Mermaid classDiagram 또는 PlantUML 클래스 | Mermaid 문서용; PlantUML 자세한 UML은 |
| project schedule | Mermaid gantt | 간결한 타임라인 구문 |
| 계층 구조, 아이디어, 메모 | Mermaid mindmap | 아이디어 맵에 좋은 기본값 |
| customer/product 여행| Mermaid journey |내장된 여행 표기법 |
| git history | Mermaid gitGraph | 내장 git 표기법 |
| 종속성 그래프, 패키지 그래프, 대규모 네트워크 | Graphviz DOT | 조밀한 그래프를 위한 더 나은 레이아웃 엔진 |
| 레이어, 클러스터, 경계가 있는 아키텍처 | Mermaid 하위 그래프가 포함된 순서도, Graphviz 클러스터 또는 PlantUML C4 스타일 | 요청된 충실도에 따라 선택 |
| 가중치 flow/sankey-like 관계 | Mermaid 지원되는 경우 sankey-beta, 지원되지 않는 경우 SVG 또는 Graphviz | Mermaid 지원은 렌더러에 따라 다를 수 있습니다. |
| 소스 언어가 잘 맞지 않는 사용자 정의 시각적 개체 | SVG | 레이아웃과 스타일을 정밀하게 제어 |

## Output policy

- 사용자가 명시적으로 이미지만 요청하지 않는 한 항상 편집 가능한 소스를 제공하세요.
- 단일 최상의 다이어그램이 기본값입니다. 정말로 유용한 경우에만 대안을 제공하십시오.
- 이전 Mermaid/PlantUML 버전에서는 렌더링되지 않을 수 있는 멋진 기능보다 안정적이고 간단한 구문을 선호하세요.
- 짧은 라벨을 사용하세요. 필요한 경우 긴 텍스트를 다이어그램 외부의 메모로 분할합니다.
- 모호한 노드 ID를 피하십시오. ASCII ID와 사람이 읽을 수 있는 라벨을 사용하세요.
- 사용자 용어는 유지하되 다이어그램 내에서는 대문자 사용을 표준화하세요.
- 기술 다이어그램의 경우 클라이언트, 서비스, 데이터베이스, 대기열, 외부 API 및 operator/user 등의 경계가 암시되는 경우 이를 포함합니다.
- 비즈니스 프로세스 다이어그램의 경우 행복한 경로, 결정 지점, 실패, 재시도 및 수동 단계가 있는 경우 이를 구분합니다.
- 불확실한 텍스트로 생성된 다이어그램의 경우 코드 뒤에 `Assumptions` 섹션을 포함하세요.

## Mermaid 생성 규칙

간단한 템플릿은 `references/diagram-patterns.md`를 참조하세요.

일반 Mermaid 규칙:
- 올바른 다이어그램 지시문(예: `flowchart TD`, `sequenceDiagram`, `erDiagram`, `gantt`, `mindmap` 또는 `journey`)으로 시작하세요.
- 순서도의 경우 사용자가 왼쪽에서 오른쪽으로 요청하지 않는 한 `flowchart TD`를 사용하세요. 아키텍처 및 파이프라인에는 `flowchart LR`를 사용하세요.
- 스윔레인 또는 아키텍처 레이어에 하위 그래프를 사용하세요. 읽을 수 있는 라벨을 사용하여 하위 그래프의 이름을 지정하세요.
- 노드 ID를 안정적이고 ASCII 전용으로 유지하세요(예: `ingest_service[Ingest Service]`).
- 구문 분석기에 혼동을 줄 수 있는 구두점이 포함된 레이블을 인용하세요.
- 분기에 결정 다이아몬드 사용: `decision{Condition?}`.
- 의미 있는 경우에만 일관된 가장자리 라벨(`-- yes -->`, `-- no -->`, `-. async.->` 또는 `== critical ==>`)을 사용하세요.
- 시퀀스 다이어그램에서는 메시지 앞에 참가자를 선언합니다. 인간의 경우 `actor`를 사용하고 시스템의 경우 `participant`를 사용합니다.
- 조건부, 선택적, 반복 및 병렬 흐름에는 `alt/else/end`, `opt/end`, `loop/end` 및 `par/and/end` 블록을 사용합니다.

## Graphviz DOT 생성 규칙

크고 조밀하거나 레이아웃에 민감한 관계 다이어그램에는 Graphviz를 사용하세요.

- 방향성 관계의 경우 `digraph G`를 선호하고 방향성 없는 네트워크의 경우 `graph G`를 선호합니다.
- 유용한 경우 상단에 레이아웃 친화적인 그래프 속성(`rankdir=LR`, `nodesep`, `ranksep` 및 `splines=true`)을 설정하세요.
- 경계 및 하위 시스템에는 `subgraph cluster_name`를 사용하세요.
- 평범한 라벨과 절제된 스타일을 사용하세요.
- 의미를 추가할 때만 가장자리 레이블을 사용하십시오.
- 많은 노드의 경우 클러스터를 사용하여 도메인별로 그룹화하고 모든 가장자리를 교차하는 무거운 작업을 피하십시오.

## PlantUML 생성 규칙

사용자가 UML을 요청하거나 공식적인 UML 표기법이 필요한 경우 PlantUML를 사용하세요.

- `@startuml` 및 `@enduml`로 다이어그램을 래핑합니다.
- 유용할 경우 `actor`, `participant`, `database`, `queue`, `collections` 또는 `component` 고정관념을 사용하세요.
- 아키텍처 경계에는 `package`, `rectangle` 또는 `node`를 사용하세요.
- 클래스 다이어그램의 경우 사용자가 자세한 세부 정보를 요청하지 않는 한 중요한 fields/methods만 포함하세요.
- 활동 다이어그램의 경우 명확한 start/end 마커와 명시적인 분기 레이블을 사용하세요.

## SVG 생성 규칙

텍스트 다이어그램 언어가 요청된 시각적 개체를 안정적으로 표현할 수 없는 경우에만 SVG를 사용하세요.

- SVG를 단순하고 접근 가능하며 편집 가능하게 유지하세요.
- `<title>` 및 의미 있는 텍스트 라벨을 포함하세요.
- 복잡한 경로보다 직사각형, 선, 화살표 및 그룹을 선호합니다.
- 외부 글꼴이나 원격 이미지를 포함하지 마십시오.

## Rendering files

사용자가 PNG/SVG/PDF를 요청하면 소스 파일을 만들고 다음을 실행합니다.

```bash
mmdc -i input.mmd -o output.svg
dot -Tpng input.dot -o output.png
java -jar plantuml.jar -tsvg input.puml
```

각 명령은 해당 렌더러가 별도로 설치되어 있을 때만 실행할 수 있습니다. 이 저장소에는 통합 렌더링 스크립트가 포함되어 있지 않습니다. 명령이 성공하고 출력 파일이 존재하지 않는 한 이미지가 렌더링되었다고 주장하지 마세요.

## Validation checklist

Before finalizing:

- 다이어그램 유형은 사용자의 작업과 일치합니다.
- 소스는 선택한 언어에 대해 구문적으로 그럴듯합니다.
- 라벨은 들어갈 만큼 짧습니다.
- 에지와 메시지 순서는 입력을 정확하게 반영합니다.
- 입력이 불완전하면 가정이 호출됩니다.
- 생성된 파일의 경우 출력이 존재하고 열리거나 크기가 0이 아닙니다.

## 공통 응답 템플릿

대부분의 다이어그램 답변에는 다음 구조를 사용하십시오.

````markdown
편집 가능한 [언어] 버전은 다음과 같습니다.

```[language]
[source]
```

Assumptions:
- [only if needed]

Rendered file: [link] [only if generated]
````

영어 사용자 요청의 경우 영어로 응답합니다. 중국어 사용자 요청의 경우 별도로 요청하지 않는 한 중국어로 응답합니다.

---

## 주문형 부트스트랩

### 자동화 기능 경계

| 도구| 자동으로 설치 가능| 설치방법| 설명|
|------|-----------|---------|------|
| Mermaid CLI (mmdc) | ✗ | `npm install -g @mermaid-js/mermaid-cli` | Mermaid를 PNG/SVG로 렌더링 |
| Graphviz (dot) | ✗ | 수동 설치 | https://graphviz.org/download/ |
| PlantUML | ✗ | Java + plantuml.jar 필요 | https://plantuml.com/download |

### 설명

이 스킬은 주로 텍스트 형식의 다이어그램 소스(Mermaid/DOT/PlantUML)를 출력하므로 로컬 렌더링 도구가 항상 필요한 것은 아닙니다. 사용자가 PNG/SVG/PDF 파일 생성을 명시적으로 요청한 경우에만 해당 렌더러가 필요합니다.

현재 큐레이션에는 자동 설치 기능이 없습니다. 렌더러를 사용할 수 없으면 소스만 반환하고 필요한 공식 설치 방법을 안내합니다.

---

## 라우팅 컨텍스트

**상류 입구**: `../../SKILL.md`(마스터 제어), `../../routing.md`
**트리거 조건**: 사용자가 "도면 다이어그램", "플로우 차트", "아키텍처 다이어그램", "공격 경로 다이어그램", "시퀀스 다이어그램", "Mermaid", "Graphviz", "PlantUML"라고 말합니다.
**다운스트림 내보내기**:
- 생성된 차트는 `../docs-generator/` 보고서에 포함될 수 있습니다.
- 공격 경로 지도는 보안 보고서의 증거 시각화로 사용할 수 있습니다.

**유사 연결 모듈**: `../docs-generator/`(보고서에 삽입된 차트)
