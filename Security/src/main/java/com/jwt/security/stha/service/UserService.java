package com.jwt.security.stha.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public interface UserService {
     UserDetailsService userDetailsService();
}
