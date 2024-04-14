package org.springcloud.msvc.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Collections;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private WebClient webClient;

    private Logger log = LoggerFactory.getLogger(UserService.class);

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        try {
            org.springcloud.msvc.auth.model.users.User user = webClient.get()
                    .uri(
                            "http://msvc-users:8001/login",
                            uri -> uri.queryParam("email", email).build()
                    )
                    .retrieve()
                    .bodyToMono(org.springcloud.msvc.auth.model.users.User.class)
                    .block();
            log.info("User login: " + user.getEmail());
            log.info("User name: " + user.getName());
            return new User(email, user.getPassword(), true, true, true, true, Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))) {
            };
        } catch (RuntimeException e) {
            String error = "Error when login, user does not exist: " + email;
            log.error(error);
            log.error(e.getMessage());
            throw new UsernameNotFoundException(error);
        }
    }
}
