package com.ibm.message.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdvisorController {
	
	@RequestMapping(value = "/welcome", method = RequestMethod.GET)
	public String sayHello() {
		return "hello world!";
	}
	
	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String login() {
		return "redirect:/welcome";
	}
}

