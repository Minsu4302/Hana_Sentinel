---
name: 작업 항목 (Work Item)
about: 한 수직 작업 = 한 Issue = 한 PR
title: "[W1-XX] "
labels: ["week-1"]
---

> 규율: 한 Issue = 한 수직 작업 = 한 PR. 값·절차의 정본은 (A) 설계확정서 / (B) 인계문서.

## 작업 (무엇을)
<!-- (B) 인계문서의 W1-XX 한 항목만. 쪼갤 수 있으면 쪼갠다. -->
- 항목(B 기준):
- 내용:

## 건드리는 경계 (해당 라벨도 부착)
- [ ] `guard:A` 입력경계  
- [ ] `guard:B` 민감정보경계  
- [ ] `guard:D` 실행경계  
- [ ] `guard:meta` 자기검증(manifest)  
- [ ] `guard:common` 전 층위 공통

## 관련 정본·manifest (정본 = (A) §3 매핑표)
- (A) 절: <!-- 예: §3.1 D.실행경계 / §1.3 ⓐ -->
- manifest 키: <!-- 예: request_token_validation -->
- 이 작업 후 목표 상태: <!-- enforced / not_implemented(→N주차) / unverifiable / disabled -->

## 완료 기준 (테스트로 증명 가능해야 함)
> "구현했다"가 아니라 "이 테스트가 통과한다". 안전 불변식은 **위조 거부**로 증명한다.
- [ ] 정상 동작 테스트:
- [ ] 위조 거부(적대적) 테스트:
- [ ] `make verify` 종료코드 0

## 금지선 사전 확인
- [ ] 이 작업은 N1~N10 금지선을 건드리지 않는다. (건드리면 코드 전에 먼저 멈추고 위험 설명 — (A) §1.3 / 지침 A)