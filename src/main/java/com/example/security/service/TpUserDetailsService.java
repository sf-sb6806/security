package com.example.security.service;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class TpUserDetailsService implements UserDetailsService {

    @Resource
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        if(!(s).equals("user")){
            throw new UsernameNotFoundException("用户不存在");
        }

        String encode = passwordEncoder.encode("123456");
        UserDetails userDetails = new User(s,encode, AuthorityUtils.commaSeparatedStringToAuthorityList("user"));
        return userDetails;
    }
}
