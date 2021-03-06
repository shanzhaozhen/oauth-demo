package com.example.authorize.config.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.time.Duration;
import java.util.UUID;


/**
 * 授权服务器配置
 * JWT：指的是 JSON Web Token，由 header.payload.signture 组成。不存在签名的JWT是不安全的，存在签名的JWT是不可窜改的。
 * JWS：指的是签过名的JWT，即拥有签名的JWT。
 * JWK：既然涉及到签名，就涉及到签名算法，对称加密还是非对称加密，那么就需要加密的 密钥或者公私钥对。此处我们将 JWT的密钥或者公私钥对统一称为 JSON WEB KEY，即 JWK。
 */
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

    /**
     *  security 挂载 Spring Authorization Server 认证服务器
     *  定义 spring security 拦击链规则
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        /*OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();

        authorizationServerConfigurer
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI));

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http
                .requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                // 开启form登录
//                .formLogin()
//                .and()
                // 忽略掉相关端点的csrf
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                // 应用 授权服务器的配置
                .apply(authorizationServerConfigurer);
        return http.formLogin(Customizer.withDefaults()).build();*/

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    /**
     * 配置客户端
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        // 使用内存作为客户端的信息库
//        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                // 客户端id 需要唯一
//                .clientId("auth")
//                .clientName("auth")
//                // 客户端密码
//                .clientSecret("{bcrypt}$2a$10$KOO.5LqjMqA/DcbvwiD9UOeA6dzHQGzUMjH8BKoil4GuxrmpfVpzK")
//                // 可以基于 basic 的方式和授权服务器进行认证
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                // 授权码
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                // 刷新token
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                // 客户端模式
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                // 密码模式
//                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
//                // 重定向url
//                // 回调地址名单，不在此列将被拒绝 而且只能使用IP或者域名  不能使用 localhost
//                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/auth-oidc")
//                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/auth-authorization-code")
//                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/auth-client-credentials")
//                .redirectUri("http://127.0.0.1:8080/authorized")
//                .redirectUri("http://auth-server:8080/login/oauth2/code/auth-oidc")
//                .redirectUri("http://auth-server:8080/login/oauth2/code/auth-authorization-code")
//                .redirectUri("http://auth-server:8080/login/oauth2/code/auth-client-credentials")
//                .redirectUri("http://auth-server:8080/authorized")
//                .redirectUri("http://www.baidu.com")
//                .redirectUri("http2://www.baidu.com")
//                // 客户端申请的作用域，也可以理解这个客户端申请访问用户的哪些信息，比如：获取用户信息，获取用户照片等
//                // OIDC支持
//                .scope(OidcScopes.OPENID)
//                // 其它Scope
//                .scope("all")
//                .scope("message.read")
//                .scope("message.write")
//                .clientSettings(ClientSettings
//                        .builder()
//                        // 是否需要用户确认一下客户端需要获取用户的哪些权限
//                        // 比如：客户端需要获取用户的 用户信息、用户照片 但是此处用户可以控制只给客户端授权获取 用户信息。
//                        // 配置客户端相关的配置项，包括验证密钥或者 是否需要授权页面
//                        .requireAuthorizationConsent(true).build())
//                .tokenSettings(TokenSettings.builder()
//                        // accessToken 的有效期
//                        .accessTokenTimeToLive(Duration.ofHours(1))
//                        // refreshToken 的有效期
//                        .refreshTokenTimeToLive(Duration.ofDays(3))
//                        // 是否可重用刷新令牌
//                        .reuseRefreshTokens(true)
//                        .build()
//                )
//                .build();

//        // 使用数据库作为客户端的信息库
//        JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
//        jdbcRegisteredClientRepository.save(registeredClient);
//        return jdbcRegisteredClientRepository;

        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * 保存授权信息，授权服务器给我们颁发来 token，那我们肯定需要保存吧，由这个服务来保存
     * @param jdbcTemplate
     * @param registeredClientRepository
     * @return
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 如果是授权码的流程，可能客户端申请了多个权限，比如：获取用户信息，修改用户信息，此Service处理的是用户给这个客户端哪些权限，比如只给获取用户信息的权限
     * @param jdbcTemplate
     * @param registeredClientRepository
     * @return
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 配置一些断点的路径，比如：获取token、授权端点 等
     * 配置 OAuth2.0 provider元信息
     * @return
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                // 配置获取token的端点路径
//                .tokenEndpoint("/oauth2/token")
                // 发布者的url地址,一般是本系统访问的根路径
                .issuer("http://auth-server:9000").build();
    }

}
