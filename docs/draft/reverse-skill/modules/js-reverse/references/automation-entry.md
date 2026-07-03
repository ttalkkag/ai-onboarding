# 자동입장

권장되는 오프닝 순서:

1. `js-reverse_new_page` 또는 `js-reverse_navigate_page` 페이지 열기
2. `js-reverse_list_network_requests` 최근 요청 보기
3. `js-reverse_get_request_initiator` 호출 스택 찾기
4. `js-reverse_list_scripts` 스크립트 범위 생성
5. `js-reverse_search_in_sources` 검색 요청 경로, 매개변수 이름, 함수 이름
6. 필요한 경우 `js-reverse_break_on_xhr` 또는 `js-reverse_set_breakpoint_on_text`

기본적으로 처음부터 `window`, `document`, `navigator`를 어떻게 채울지 추측하지 마세요.
