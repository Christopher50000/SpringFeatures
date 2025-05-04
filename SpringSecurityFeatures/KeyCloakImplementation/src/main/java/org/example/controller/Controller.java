package org.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class Controller {

    @GetMapping("/helloUser")
    public String helloUser()
    {
        return "Hello User";
    }

    @GetMapping("/helloAdmin")
    public String helloAdmin()
    {
        return "Hello Admin";
    }
}

