package com.prgrms.devcourse.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;

    private String credentials;

    // 인증 요청시 호출되는 생성자 (초기 아이디, 비밀번호로 요청할 때)
    public JwtAuthenticationToken(String principal, String credentials) {
        super(null);    // 아직 인증되지 않은 사용자기 때문에 권한을 Null 로 설정
        super.setAuthenticated(false);

        this.principal = principal;
        this.credentials = credentials;
    }

    // 인증이 완료됐을 때 호출되는 생성자
    JwtAuthenticationToken(Object principal, String credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        super.setAuthenticated(true);

        this.principal = principal;
        this.credentials = credentials;
    }

    @Override
    public String getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException("Cannot set this token to trusted.");
        }
        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}
