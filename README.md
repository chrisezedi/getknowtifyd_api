## BACKEND API FOR GETKNOWTIFYD APP  

### Technologies Used  
- Django V3.11
- Django Rest Framework
- Amazon SES (For sending mail)
- Amazon ECR/ECS
- Amazon RDS (MySQL)
- Docker  

###  How to Run (DEV)
#### RUN Migration
`python manage.py makemigrations && python manage.py migrate` 

###  How to Run Test
`pytest`  

[![GNTF Tests](https://github.com/chrisezedi/getknowtifyd_api/actions/workflows/aws.yml/badge.svg)](https://github.com/chrisezedi/getknowtifyd_api/actions/workflows/aws.yml)