package com.prgrms.devcourse.configures;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationEventHandler {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Async
    @EventListener
    public void handleAuthenticationSuccessEvent(AuthenticationSuccessEvent event) {
        // Event 발행과 처리는 동기적으로 이루어지기 때문에 여기서 처리가 늦어지면 전체적인 시스템 처리 속도에 영향을 준다 (Async 활용 가능)
        try { Thread.sleep(5000); } catch (InterruptedException ignored) { }

        Authentication authentication = event.getAuthentication();
        logger.info("Successful authentication result: {}", authentication.getPrincipal());
    }

    @EventListener
    public void handleAuthenticationFailureEvent(AbstractAuthenticationFailureEvent event) {
        Exception exception = event.getException();
        Authentication authentication = event.getAuthentication();
        logger.warn("Unsuccessful authentication result: {}", authentication, exception);
    }
}
