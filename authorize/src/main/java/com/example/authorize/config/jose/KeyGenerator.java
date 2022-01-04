package com.example.authorize.config.jose;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

@Configuration
@RequiredArgsConstructor
public class KeyGenerator {

	private final JwtConfig jwtConfig;

//	@SneakyThrows
//	@Bean
//	public KeyPair generateRsaKey() {
//		ClassPathResource resource = new ClassPathResource(jwtConfig.getPath());
//		KeyStore jks = KeyStore.getInstance("jks");
//		char[] pin = jwtConfig.getPassword().toCharArray();
//		jks.load(resource.getInputStream(), pin);
//		return RSAKey.load(jks, jwtConfig.getAlias(), pin).toKeyPair();
//	}

	@SneakyThrows
	@Bean
	public KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

}
