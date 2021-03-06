# kotlin-social-login-demo
- social login demo using kotlin and spring boot

## Description
- local login and social login(only google)
- If user sign in, user get refresh token(cookie), and access token(response body).

## Setting
- Add application-jwt.yml in resources directory.
- application-jwt.yml format
```yaml
jwt:
    issuer: issur
    secret-key: key
```
- Add application-oauth2.yml in resources directory.
- application-oauth2.yml format
```yaml
oauth2:
    clients:
        google:
            client-id: id
            client-secret: secret
```

## API
### sign-up
- POST /api/account/signup
#### Request
- request body
```
email: String,
password: String,
name: String
```
#### Response
- 201 created
- response body
```
id: Long,
email: String,
name: String,
createdAt: LocalDateTime
```
### local login
- POST /login
#### Request
- request body
```
email: String,
password: String
```
#### Response
- response cookie
```
_ret: refresh_token
```
- response body
```
token: access_token
```
### social login
- http://localhost:8080/oauth2/authorization/{provider}
#### Response
- same local login

### Refresh Token
- POST /refresh_token
#### Request
- cookie
```
_ret: refresh_token
```
#### Response
- same local login

## Reference
- https://www.callicoder.com/spring-boot-security-oauth2-social-login-part-1/
- https://woowabros.github.io/experience/2020/05/11/kotlin-hibernate.html
- https://github.com/tuguri8/d2-timeline-api
- https://hasura.io/blog/best-practices-of-using-jwt-with-graphql/
- https://m.blog.naver.com/PostView.nhn?blogId=anytimedebug&logNo=221396422266&categoryNo=28&proxyReferer=http:%2F%2Fblog.naver.com%2FPostView.nhn%3FblogId%3Danytimedebug%26logNo%3D221396422266%26parentCategoryNo%3D%26categoryNo%3D28%26viewDate%3D%26isShowPopularPosts%3Dfalse%26from%3DpostView

## ToDo
1. Add exceptions, Now all RuntimeException.
2. Now use InMemoryOAuth2AuthorizedClientService, change db base.
3. Add other oauth2 login. (github, facebook, naver, kakao, etc)
4. Add global logout. 
5. Validate request.
