package com.iotauth.iot_auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class IotAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(IotAuthApplication.class, args);
	}

}
