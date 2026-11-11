# Butler
# Butler Core

**Butler** is a lightweight, modular, and self-hosted backend service built with Spring Boot. It allows you to easily plug in new modules and extend its functionality to suit your needs.

> ** Work in Progress (WIP)**: This project is currently under active development. Features, APIs, and structure are subject to change.

## Key Features

- **Self-Hosted & Containerized:** Fully prepared to run locally or on your own server using Docker and PostgreSQL.
- **Modular Architecture:** Clean separation of concerns (Core, Security, and future custom domains/modules).
- **Lightweight Custom Security:** Centralized custom filtering (`VerificationFilter`) supporting API Keys (`X-API-Key`) and HTTP Basic Authentication.
- **Extensible Design:** Built to scale horizontally by adding new modules without cluttering the core application logic.

---

## Tech Stack

- **Backend:** Java 17+, Spring Boot, Spring Security (Core filter-based), Spring Data JPA / Hibernate
- **Database:** PostgreSQL
- **Containerization:** Docker & Docker Compose

---
