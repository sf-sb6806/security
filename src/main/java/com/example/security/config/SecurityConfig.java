package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

   /* @Override
    内存设置密码 security登录
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("123456")
                .roles("user");
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                //自定义登录页面
                .loginPage("/login.html")
                //必须和表单提交的接口路径一致，会去执行自定义登录逻辑
                .loginProcessingUrl("/login")
                //登录成功后跳转到的页面，只接受post请求
                .successForwardUrl("/toMain");

        http.authorizeRequests()
                //放行路径
                .antMatchers("/login.html").permitAll()
                //除了放行的路径其他的路径都需要授权
                .anyRequest().authenticated();

        //关闭crsf防护
        http.cors().disable();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
