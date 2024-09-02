package com.jwt.security.stha.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/user/msg")
    public String fromUser() {
        return "This message is from User";
    }

    @GetMapping("/admin/msg")
    public String fromAdmin() {
        return "This message is from admin";
    }
}
