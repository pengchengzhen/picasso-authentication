package com.thinking.picasso.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * @Author: chengZhen
 * @Date: 2020/12/14/16:58
 */
@Configuration
@RequiredArgsConstructor
public class TokenConfiguration {

    @Bean
    public TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }

}
