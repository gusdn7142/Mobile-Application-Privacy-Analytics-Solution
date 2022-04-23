# Mobile-Application-Privacy-Analytics-Solution
>케이쉴드 주니어 6기 팀 프로젝트 (중국 모바일 어플리케이션의 개인정보 수집과 활용에 관한 분석 및 자동화 방안 연구)
- WBS : https://docs.google.com/spreadsheets/d/1d2tecmpHMVD-wx-GOQ8MbFO2gaJowiYg/edit#gid=1967809667

</br>

## 1. 프로젝트 배경
  - 국내에서 카메라, SNS, 게임 등 다방면에서 중국산 어플리케이션 점유율 증가
  - 개인정보처리방침에 기재된 내용을 넘어서 사용자의 개인정보를 과도하게 수집하고 유출하는 어플리케이션의 문제점 대두
  - 우리나라 국민의 낮은 개인정보보호 의식 수준

</br>

## 2. 제작 기간 & 참여 인원  
- 2021년 12월 11일 ~ 12월 25일  
- 팀 구성 (총 10명)
    - 팀장 : 길예슬 
    - PM : 최현우   
    - PL : 김경태 
    - 팀원 : 박지형, 정지훈, 조민지, 김정수, 양지안, 조성민, 이혜지  
</br>

## 3. 사용 기술
#### `분석 대상 어플리케이션 (10개)`
  - Ali Express
  - Bigo Live
  - Camera 360
  - Makeup Plus
  - Shareit
  - TikTok
  - ULike
  - WeChat
  - YouCam Makeup

#### `프로젝트 환경 & 툴`  
  - OS : Kali Linux, Windows
  - Mobile : Noxplayer
  - Analysis tool 
      - Static analysis : mobSF, JADX, JEB     
      - Dynamic analysis : Frida, Drozer, ADB, Fiddler, WireShark   
   
#### `프로그래밍 언어`
  - Javascript
  - Python

</br>


## 4. 분석 방법
  - 정적 분석 
    - 개념 : 어플리케이션을 실행하지 않고 소스 코드를 통해 어플리케이션의 구조와 기능을 파악하는 분석 기법
    - 프로세스 :  
      ➤ 개인정보처리방침을 분석한 후, 활용 용도 별로 개인정보를 분류  
      ➤ 개인정보와 관련된 퍼미션 분석  
      ➤ 개인정보처리방침의 내용과 개인정보와 관련된 퍼미션을 바탕으로 개인정보와 관련된 소스코드를 추출하여 동적 분석에 참고할 수 있는 코드 정보 추출, 코드 구조 이해

  - 동적 분석 
    - 개념 : 어플리케이션을 직접 실행하여 어플리케이션의 구조와 기능을 파악하는 분석 기법
    - 프로세스 :  
      ➤ 앱을 실행시켜보며 실제 대상 서비스에서 개인정보 데이터가 저장, 활용되는 기능을 분류  
      ➤ Frida API를 이용하여 Code Injection을 통해 해당 기능이 실행되는 클래스와 메소드 추적  
      ➤ 발견한 메소드, 클래스 부분의 코드를 살펴보며 기능의 동작 방식을 파악하고 구체적으로 어떤 데이터를 저장하고, 패킷으로 전송하는지 살펴본다.

</br>

## 4. 핵심 기능
  - 동적 분석시 활용하기 위한 특정 기능에 활용되는 데이터 추적 코드 구현
    - raptor_frida_android_trace.js : 앱 실행 시 호출되는 함수 추적
    - Local_variable_check.py : 특정 함수에 정의된 지역 변수 값 확인

</br>

## 5. 핵심 트러블 슈팅
>추후 추가 예정

</br>

## 6. 회고 / 느낀점
>프로젝트 개발 회고 글: 
