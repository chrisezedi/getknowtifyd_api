resource "aws_ecs_cluster" "ecs" {
  name = "gntf_cluster"
}

resource "aws_ecs_service" "service" {
  name = "gntf_service"
  cluster                = aws_ecs_cluster.ecs.arn
  launch_type            = "FARGATE"
  enable_execute_command = true

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100
  desired_count                      = 1
  task_definition                    = aws_ecs_task_definition.td.arn

  network_configuration {
    assign_public_ip = true
    security_groups  = [aws_security_group.sg.id]
    subnets          = [aws_subnet.sn1.id, aws_subnet.sn2.id, aws_subnet.sn3.id]
  }
}

resource "aws_ecs_task_definition" "td" {
  container_definitions = jsonencode([
    {
      name         = "gntf_app"
      image        = "931574259411.dkr.ecr.us-east-1.amazonaws.com/getknowtifyd"
      cpu          = 256
      memory       = 512
      essential    = true
      portMappings = [
        {
          containerPort = 80
          hostPort      = 80
        }
      ]
    }
  ])
  family                   = "app"
  requires_compatibilities = ["FARGATE"]

  cpu                = "256"
  memory             = "512"
  network_mode       = "awsvpc"
  task_role_arn      = "arn:aws:iam::931574259411:role/ecsTaskExecutionRole"
  execution_role_arn = "arn:aws:iam::931574259411:role/ecsTaskExecutionRole"
}