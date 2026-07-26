# 기호 마이그레이션 프롬프트 템플릿

## 표준 비교 프롬프트(직접 복사하여 사용)

````text
동일한 함수의 디스어셈블리 출력과 프로시저 코드가 있습니다.

다음은 참조할 함수입니다.

**참조 디스어셈블리**
```c
{disasm_for_reference}
```

**참조 프로시저 코드**
```c
{procedure_for_reference}
```

다음은 리버스 엔지니어링해야 하는 함수입니다.

**리버스 엔지니어링 대상 디스어셈블리**
```c
{disasm_code}
```

**리버스 엔지니어링 대상 프로시저 코드**
```c
{procedure}
```

해야 할 일은 리버스 엔지니어링 대상 함수 안에서 "{symbol_name_list}"에 대한 모든 참조를 수집하고, 해당 참조를 YAML로 출력하는 것입니다.

예시:
```yaml
found_vcall:
  - insn_va: '0x180777700'
    insn_disasm: call qword ptr [rax+68h]
    vfunc_offset: '0x68'
    func_name: ILoopMode_OnLoopActivate

found_call:
  - insn_va: '0x180888800'
    insn_disasm: call sub_180999900
    target_va: '0x180999900'
    func_name: CLoopMode_RegisterEventMapInternal

found_funcptr:
  - insn_va: '0x180666600'
    insn_disasm: lea rdx, sub_15BC910
    target_va: '0x15BC910'
    funcptr_name: CLoopMode_OnClientPollNetworking

found_gv:
  - insn_va: '0x180444400'
    insn_disasm: mov rcx, cs:qword_180666600
    target_va: '0x180666600'
    gv_name: g_pNetworkMessages

found_struct_offset:
  - insn_va: '0x1801BA12A'
    insn_disasm: mov rcx, [r14+58h]
    offset: '0x58'
    size: 8
    struct_name: CResourceService
    member_name: m_pEntitySystem
```

아무것도 찾지 못하면 빈 YAML을 출력하세요. 원하는 YAML 외에는 아무것도 출력하지 마세요. 관련 없는 심볼은 수집하지 마세요.
````

## 변수 채우기 지침

| 변수| 소스| 얻는 방법|
|------|------|---------|
| `{disasm_for_reference}` |이전 버전 IDA| `idapro_disasm(addr="함수명")` |
| `{procedure_for_reference}` |이전 버전 IDA| `idapro_decompile(addr="함수명")` |
| `{disasm_code}` | 새 버전 IDA| `idapro_disasm(addr="해당_주소")` |
| `{procedure}` | 새 버전 IDA| `idapro_decompile(addr="해당_주소")` |
| `{symbol_name_list}` | 이전 버전 추출| 참조 코드에서 sub_/loc_ 기호가 아닌 모든 기호 이름을 추출합니다.|

## 일괄 호출 스크립트 뼈대(Python)

아래 코드와 같은 디렉터리의 `prompt-template.txt`에는 이 문서 전체가 아니라 위 4중 코드 펜스 안의 프롬프트 본문만 저장하세요.

```python
import yaml
import httpx

PROMPT_TEMPLATE = open("prompt-template.txt", encoding="utf-8").read()

def migrate_function(ref_disasm, ref_procedure, target_disasm, target_procedure, symbols, api_url, api_key, model):
    prompt = PROMPT_TEMPLATE.format(
        disasm_for_reference=ref_disasm,
        procedure_for_reference=ref_procedure,
        disasm_code=target_disasm,
        procedure=target_procedure,
        symbol_name_list=", ".join(symbols)
    )

    resp = httpx.post(api_url, json={
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0
    }, headers={"Authorization": f"Bearer {api_key}"}, timeout=60)
    resp.raise_for_status()

    content = resp.json()["choices"][0]["message"]["content"]

    # YAML 블록 추출
    if "```yaml" in content:
        yaml_str = content.split("```yaml")[1].split("```")[0]
    elif "```" in content:
        yaml_str = content.split("```")[1].split("```")[0]
    else:
        yaml_str = content

    return yaml.safe_load(yaml_str)


def build_candidate_plan(results):
    """파싱된 YAML에서 검증 전 후보 계획을 생성(IDA에는 쓰지 않음)"""
    if not results:
        return

    renames = []
    comments = []

    if "found_call" in results:
        for item in results["found_call"]:
            int(item["target_va"], 0)  # 주소 형식 검증; IDA 피연산자와 별도 대조 필요
            renames.append({"addr": item["target_va"], "name": item["func_name"], "type": "call_target"})

    if "found_funcptr" in results:
        for item in results["found_funcptr"]:
            int(item["target_va"], 0)
            renames.append({"addr": item["target_va"], "name": item["funcptr_name"], "type": "funcptr_target"})

    if "found_gv" in results:
        for item in results["found_gv"]:
            int(item["target_va"], 0)
            renames.append({"addr": item["target_va"], "name": item["gv_name"], "type": "gv"})

    if "found_vcall" in results:
        for item in results["found_vcall"]:
            comments.append({
                "addr": item["insn_va"],
                "comment": f"vcall: {item['func_name']} @ +{item['vfunc_offset']}"
            })

    if "found_struct_offset" in results:
        for item in results["found_struct_offset"]:
            comments.append({
                "addr": item["insn_va"],
                "comment": f"{item['struct_name']}.{item['member_name']} @ +{item['offset']}"
            })

    return {"renames": renames, "comments": comments}
```

## API 구성 제안

```yaml
# 이 코드는 OpenAI 호환 Chat Completions 응답 형식용 예시입니다.
default:
  api_url: "https://provider.example/v1/chat/completions"
  model: "reviewed-model-id"
```

제공자마다 인증 헤더와 요청·응답 형식이 다릅니다. 특히 Anthropic Messages API는 위 코드의 Chat Completions 파서와 호환되지 않으므로 별도 어댑터를 사용하세요. 모델 ID는 실행 시점의 공식 제공자 문서와 내부 평가를 기준으로 설정합니다.
