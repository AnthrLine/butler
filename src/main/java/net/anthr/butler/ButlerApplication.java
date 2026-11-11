package net.anthr.butler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {"net.anthr.butler"})
public class ButlerApplication {

	public static void main(String[] args) {
		System.out.println("Main executat");
        SpringApplication.run(ButlerApplication.class, args);
	}

}
