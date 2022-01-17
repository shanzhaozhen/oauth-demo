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
   - `expandRedirectUri` 方法，会构造 `redirectUri` 得到 `http://auth-server:8080/login/oauth2/code/auth-oidc` ，授权服务器认证通过后则会跳回该地址
   - 最后会得到 `OAuth2AuthorizationRequest` 这包含了客户端的信息和将要跳转的地址，通过 `sendRedirectForAuthorization` 跳转到认证服务器。（最终构造的url为 `http://auth-server:9000/oauth2/authorize?response_type=code&client_id=auth&scope=openid&state=xxx&redirect_uri=http://auth-server:8080/login/oauth2/code/auth-oidc&nonce=xxx` ）

#### 授权服务器

1. 接收到客户端的认证请求，进入 `OAuth2AuthorizationEndpointFilter` 过滤器（拦截 `/login/oauth2/**` 端点）
2. 然后进入 `OAuth2AuthorizationCodeRequestAuthenticationProvider` 认证提供商的 `authenticateAuthorizationRequest` 方法进行鉴权，报 `AccessDeniedException` 异常
   - 这里会校验在注册进授权服务器的 `Client Registration` 中支不支持客户端传过来的 `redirectUri` 、 `scope`
3. 通过 `handleAccessDeniedException` 异常捕获，跳转到到 `LoginUrlAuthenticationEntryPoint` 中 `commence()` 方法处理，跳转到登陆页面。
6. `redirect` 跳转到设置的登陆页(demo中为 `/login` )。
7. 然后经过一系列过滤链，最终在 `DefaultLoginPageGeneratingFilter` 过滤连返回登录页给用户

***

### 二、登陆过程

#### 授权服务器

1. 在登陆页面输入用户名和密码
2. 首先会认证用户名和密码，进入关键过滤连 `AbstractAuthenticationProcessingFilter` ==> `UsernamePasswordAuthenticationFilter` ，（拦截`/login` 端点）
   - 会进入关键的 `UserDetailsService` 具体的实现类中（demo 使用了 `InMemoryUserDetailsManager` ），获取用户信息 `UserDetails`
3. 登陆认证成功后，会在 `SavedRequestAwareAuthenticationSuccessHandler` 类中的 `onAuthenticationSuccess` 方法做跳转处理，从session的获取第一次访问授权服务器的 url 作跳转( `http://auth-server:9000/oauth2/authorize?response_type=code&client_id=auth&scope=openid&state=xxx&redirect_uri=http://auth-server:8080/login/oauth2/code/auth-oidc&nonce=xxx` )
4. 重新进入授权服务器，将会认证客户端信息，经过 `OAuth2AuthorizationEndpointFilter` 过滤器
5. 然后进入 `OAuth2AuthorizationCodeRequestAuthenticationProvider` 认证提供商的 `authenticateAuthorizationRequest` 方法进行鉴权
   - 这次鉴权通过后会调用 `generateAuthorizationCode()` 方法生成 code
   - 构建 `OAuth2Authorization` 保存到数据库，用来下次一访问授权服务器带上code做校验使用
6. 最后会进入 `sendAuthorizationResponse` 方法中，携带 `code` 数据返回给客户端，（url 为 `http://auth-server:8080/login/oauth2/code/auth-oidc?code=xxx` ）

#### 客户端

1. 接收到授权服务器传回来的 `code` ，将会被 `OAuth2LoginAuthenticationFilter` 过滤链拦截（拦截端点：`/login/oauth2/code/*` ），进入 `attemptAuthentication` 方法
   - 从 `request` 获取 `code` 的值
   - 获取 `authorizationRequest` ，第一次取出来的值为null，这将会重新发送一次认证请求到授权服务器。过程将会跳转到 `/oauth2/authorization/auth-oidc?error` ,拦截错误后将会重新走一次上面提到的“认证页面获取过程”中客户端的第 4 点过程，然后回到这里
   - 第二次进入该方法，顺利通过 `authorizationRequest` 判断
   - 进入 `OidcAuthorizationCodeAuthenticationProvider` 认证提供商的进行鉴权

***