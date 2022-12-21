package com.prgrms.devcourse.configures;

import com.prgrms.devcourse.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {
    private final Logger logger = LoggerFactory.getLogger(WebSecurityConfigure.class);

    private UserService userService;

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @Bean
    @Qualifier("myAsyncTaskExecutor")
    public ThreadPoolTaskExecutor threadPoolTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);
        executor.setMaxPoolSize(5);
        executor.setThreadNamePrefix("my-executor-");
        return executor;
    }

    @Bean
    public DelegatingSecurityContextAsyncTaskExecutor taskExecutor(@Qualifier("myAsyncTaskExecutor") AsyncTaskExecutor delegate) {
        return new DelegatingSecurityContextAsyncTaskExecutor(delegate);
    }

//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//        JdbcDaoImpl jdbcDao = new JdbcDaoImpl();
//        jdbcDao.setDataSource(dataSource);
//        jdbcDao.setEnableAuthorities(false);
//        jdbcDao.setEnableGroups(true);
//        jdbcDao.setUsersByUsernameQuery("SELECT login_id, password, true FROM users WHERE login_id = ?");
//        jdbcDao.setGroupAuthoritiesByUsernameQuery(
//                "SELECT u.login_id, g.name, p.name\n" +
//                "FROM users u JOIN groups g ON u.group_id = g.id\n" +
//                "LEFT JOIN group_permission gp ON g.id = gp.group_id\n" +
//                "JOIN permissions p ON p.id = gp.permission_id\n" +
//                "WHERE u.login_id = ?"
//        );
//
//        return jdbcDao;
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/assets/**", "/h2-console/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/me", "/asyncHello", "/someMethod").hasAnyRole("USER", "ADMIN")
                    .antMatchers("/admin").access("hasRole('ADMIN') and isFullyAuthenticated()")
                    .anyRequest().permitAll()
//                    .expressionHandler(securityExpressionHandler())
//                    .accessDecisionManager(accessDecisionManager())
                    .and()
                .formLogin()
                    .defaultSuccessUrl("/")
                    .permitAll()
                    .and()
                .httpBasic()
                    .and()
                .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                    .logoutSuccessUrl("/")
                    .invalidateHttpSession(true)
                    .clearAuthentication(true)
                    .and()
                .rememberMe()
                    .key("my-remember-me") // key 값을 지정해주지 않으면 서버 재시작 시 랜덤한 문자열이 지정됨
                    .rememberMeParameter("remember-me")
                    .tokenValiditySeconds(300)
    //                .alwaysRemember(false)
                    .and()
                // SSL(TLS) 인증서 설정
                .requiresChannel()
                    .anyRequest().requiresSecure()
                    .and()
                .anonymous()
                    .principal("thisIsAnonymousUser")
                    .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
                    .and()
                .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler())
                    .and()
                .sessionManagement()
                    .sessionFixation().changeSessionId()
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .invalidSessionUrl("/")
                    .maximumSessions(1)
                    .maxSessionsPreventsLogin(false);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("user").password("{noop}user123").roles("USER")
//                .and()
//                .withUser("admin01").password("{noop}admin123").roles("ADMIN")
//                .and()
//                .withUser("admin02").password("{noop}admin123").roles("ADMIN");

//        auth.jdbcAuthentication()
//                .dataSource(dataSource)
//                .usersByUsernameQuery("SELECT login_id, password, true FROM users WHERE login_id = ?")
//                .groupAuthoritiesByUsername(
//                        "SELECT u.login_id, g.name, p.name\n" +
//                        "FROM users u JOIN groups g ON u.group_id = g.id\n" +
//                        "LEFT JOIN group_permission gp ON g.id = gp.group_id\n" +
//                        "JOIN permissions p ON p.id = gp.permission_id\n" +
//                        "WHERE u.login_id = ?")
//                .getUserDetailsService().setEnableAuthorities(false);

        auth.userDetailsService(userService);
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (httpServletRequest, httpServletResponse, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            logger.warn("{} is denied", principal, e);
            httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            httpServletResponse.setContentType("text/plain");
            httpServletResponse.getWriter().write("## ACCESS DENIED ##");
            httpServletResponse.getWriter().flush();
            httpServletResponse.getWriter().close();
        };
    }

    public SecurityExpressionHandler<FilterInvocation> securityExpressionHandler() {
        return new CustomWebSecurityExpressionHandler(
                new AuthenticationTrustResolverImpl(),
                "ROLE_"
        );
    }

//    @Bean
//    public AccessDecisionManager accessDecisionManager() {
//        List<AccessDecisionVoter<?>> voters = new ArrayList<>();
//        voters.add(new WebExpressionVoter());
//        voters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));
//
//        return new UnanimousBased(voters);
//    }
}
