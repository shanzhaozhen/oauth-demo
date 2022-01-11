# Oauth Demo

Oauth2 的文档太多了，而且 Spring 也出了个新产品 `spring-authorization-server` ，没整明白，所以自己 debug 整理这个 Oauth2 认证的过程。

### Oauth2 客户端跳转过程

### 一、认证页面获取过程

#### 客户端

1. 登陆无权限拦截，被 `AbstractSecurityInterceptor` 拦截器拦截，报 `AccessDeniedException` 异常
2. 通过 `handleAccessDeniedException` 异常捕获，跳转到到 `LoginUrlAuthenticationEntryPoint ` 中 `commence()` 方法处理，跳转到登陆页面。
3. `redirect` 跳转到设置的登陆页(demo中为 `/oauth2/authorization/auth-oidc` )。
4. 关键过滤器`OAuth2AuthorizationRequestRedirectFilter` 拦截，进入 `doFilterInternal()` 方法后会转到 `DefaultOAuth2AuthorizationRequestResolver` 类中的 `resolve` 方法处理，该方法有很多重载方法
   - 进入 `resolve` 方法，匹配 `/oauth2/authorization/**` 获得 `registrationId` (demo中为 `auth-oidc`)
   - 进入另一个 `resolve` 重载方法，通过 `registrationId` 从内存中获取注册了的客户端信息 `Client Registration`，即配置文件注入的 `Oauth Client` 信息
   - `expandRedirectUri` 方法，会构造 `redirectUri` 得到 `http://127.0.0.1:8080/login/oauth2/code/auth-oidc` ，授权服务器认证通过后则会跳回该地址
   - 最后会得到 `OAuth2AuthorizationRequest` 这包含了客户端的信息和将要跳转的地址，通过 `sendRedirectForAuthorization` 跳转到认证服务器。（最终构造的url为 `http://auth-server:9000/oauth2/authorize?response_type=code&client_id=auth&scope=openid&state=vG1lAOLSlimrDP64KOBMDTJbTJRcui9vj6y0sy4mN7w%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/auth-oidc&nonce=qYHKe3DzbfWEUmMtmyL1_x0IlW1zG_FbfOcpwdGGVxo` ）

#### 授权服务器

1. 接收到客户端的认证请求，进入 `OAuth2AuthorizationEndpointFilter` 过滤器（拦截 `/login/oauth2/**` 端点）
2. 然后进入 `OAuth2AuthorizationCodeRequestAuthenticationProvider` 认证提供商的 `authenticateAuthorizationRequest` 方法进行鉴权，报 `AccessDeniedException` 异常
   - 这里需要确认跳转的的 `redirectUri` 在注册进授权服务器的 `Client Registration` 中的 `redirectUri` 是否包含其中
3. 通过 `handleAccessDeniedException` 异常捕获，跳转到到 `LoginUrlAuthenticationEntryPoint ` 中 `commence()` 方法处理，跳转到登陆页面。
6. `redirect` 跳转到设置的登陆页(demo中为 `/login` )。
7. 然后经过一系列过滤链，最终在 `DefaultLoginPageGeneratingFilter` 过滤连返回登录页给用户

***

### 二、登陆过程

1. 在登陆页面输入用户名和密码
2. 进入关键过滤连 `AbstractAuthenticationProcessingFilter` ==> `UsernamePasswordAuthenticationFilter` ，（拦截`/login` 端点）
3. 会进入关键的 `UserDetailsManager` 类从内存或数据源中（看你的实现方式，demo 默认使用了内存 `InMemoryUserDetailsManager` ）获取用户信息 `UserDetails`
4. 
5. 登陆通过后会进入 `AbstractAuthenticationProcessingFilter` 过滤连，开始鉴权
6. 鉴权通过后最终进入 `SavedRequestAwareAuthenticationSuccessHandler` 的 `onAuthenticationSuccess` 方法
7. 

***