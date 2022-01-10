package com.example.authorize;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthorizeApplication {

    public static void main(String[] args) {
        // 关闭druid ping 警告
        System.setProperty("druid.mysql.usePingMethod", "false");
        SpringApplication.run(AuthorizeApplication.class, args);
    }

}
