### refresh token 관리

	refresh token은 access token이 발급될 때 함께 제공
	refresh token을 사용하여 access token을 재발급 받을 수 있다
	access token은 발급 후 2시간, refresh token은 발급 후 14일 후 만료
	refresh token는 access token 재발급 시에만 사용(access token 처럼 사용X)

	refresh token 을 발급시에는 issuer 데이터를 새로 만들어 디비에 저장
		- issuer 데이터는 현재 [회원id_idx] 형식이며 idx를 +1 하는 형식
		- 초기 로그인 성공 후, refresh token 재발급 시
		- 긴 refresh token 대신 위 경우마다 새 issuer를 발급해서 토큰에 넣고 비교
	refresh token 으로 access token 재발급시에는 client에서 주는 refresh token과 db의 refresh token을 비교 
	재발급으로 사용된 refresh token은 폐기되고 new refresh token을 생성, 발급 새 issuer를 db에 저장 한다.


### API 요청 함수

로그인 => access token, refresh token 발급   
refresh token으로 access token 발급   
만료 전 refresh token 으로 new access token, new refresh token 발급   


###  access token 재발급 flow

Client --------------------------------------------- API 서버

--------- 로그인 ----------------------------------------->   
<-------- access token 발급(+refresh token) ---------------     
--------- access token 을 사용하여 API request ----------->    
<-------- access token 만료 에러 response -----------------    
--------- refresh token 으로 access token 재발급 요청 ----->   
<-------- access token 재발급 -----------------------------     



### 회원정보

	초기 로그인 성공 후에 access token 과 함께 회원 정보를 전달하고 token에는 중요한 개인 정보는 담지 않는다.
	access token에는 유저 키값이나 타입정도만 payload에 넣는다.(base64로 디코딩 하여 token 내용을 볼 수 있으므로)

	로그아웃의 경우 디비에 issuer data  삭제 처리
