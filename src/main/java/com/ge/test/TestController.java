package com.ge.test;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class TestController {

	@RequestMapping("api/login")
	public String login(String username, String password) {
		return username + ":" + password;
	}

	@RequestMapping("api/msg")
	public String msg() {
		return "abc";
	}

	@RequestMapping("api/ctx")
	public String ctx() {
		return SecurityContextHolder.getContext().getAuthentication().toString();
	}
}
