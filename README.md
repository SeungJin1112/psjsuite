# psjSuite

<div align="center">
  <img src="https://capsule-render.vercel.app/api?color=gradient&type=rect&section=header&text=psjSuite&fontSize=40&animation=fadeIn" alt="psjSuite"/>
</div>

## 프로젝트 개요
본 저장소는 문서 변환·뷰잉 파이프라인을 실험·검증하는 연구·개발용 프로젝트입니다.  
여러 실험 샘플을 통해 **메모리 매핑 기반 실행**, **포맷 파싱·변환**, **출력 뷰어 및 편집기 기능**까지 통합하는 것을 장기 목표로 합니다.

## 🧭 개발 목표
아직 최종 범위는 확정되지 않았으나, 아래 개발 항목들을 단계적으로 통합하는 것을 목표로 하고 있습니다.

## ⚙️ 개발 사항 (진행 현황)

✅ 항목 1. sample-0001
- **목적:** Windows / Linux 크로스플랫폼 빌드 테스트  
- **내용:** OS 독립적인 빌드 환경 구성 및 실행 검증

✅ 항목 2. sample-windows-0001
- **목적:** Windows NTAPI 기반 mapped-image injector 구현  
- **핵심:** NtCreateSection, NtMapViewOfSection 기반 메모리 매핑 인젝션  
- **특징:** 아키텍처(x86/x64/ARM 등) 구분 없이 주입 가능하도록 설계  
- **비고:** 연구 및 테스트 목적으로만 사용

🧩 항목 3. sample-windows-0002
- **목적:** HWP, HWPX, PPTX, DOCX... → XML 및 바이너리 파싱 → PDF 변환 또는 자체 확장자 변환  
- **상태:** XML 구조 해석 및 PDF 변환 파이프라인 구축 중  
- **활용:** 문서 자동 변환, 아카이빙, 포맷 분석 도구

🧾 항목 4.
- **내용:** 2번 + 3번 통합 → 캡처 감지 및 녹화 감지 시 자동 제어 기능 탑재  
- **예시:** 화면 캡처 탐지 시 문서 접근 차단 또는 경고 처리

🧾 항목 5.
- **내용:** 자체 확장자 출력 뷰어 및 노이즈 프린팅(워터마크 등) 기능 추가  
- **목표:** 보안 뷰어 및 출력 제어 시스템 구현

🧾 항목 6.
- **내용:** 자체 에디터 및 뷰어 개발 → 고객 배포용 버전 제공  
- **기능:** 문서 열람, 편집, PDF 출력, 보안 워터마크 인쇄 등

## 🧱 샘플별 요약

| 샘플명 | 목적 | 상태 | 주요 기술 |
|:--|:--|:--|:--|
| sample-0001 | 크로스플랫폼 빌드 테스트 | 완료 | Visual Studio (MSVC), Make |
| sample-windows-0001 | NTAPI 기반 Mapped Image Injector | 완료 | NtCreateSection, NtMapViewOfSection |
| sample-windows-0002 | 문서 포맷 파싱 및 PDF 변환 | 개발 중 | XML Parsing, Zip 구조 해석, PDF Generator |

## 🧰 개발 환경

| 구분 | 요구사항 |
|:--|:--|
| **Windows** | Visual Studio (MSVC) |
| **Linux** | GCC, Make |
| **공통** | C/C++17 이상, 문서 처리용 라이브러리 등 |
| **기타** | Python (테스트 스크립트 또는 변환 자동화 시 보조 용도) |
