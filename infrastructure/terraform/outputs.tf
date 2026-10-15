output "vpc_id" {
  value = aws_vpc.main.id
}

output "database_endpoint" {
  value = aws_db_instance.postgres.address
}

output "redis_endpoint" {
  value = aws_elasticache_cluster.redis.cache_nodes[0].address
}

output "load_balancer_dns" {
  value = aws_lb.main.dns_name
}

output "report_bucket" {
  value = aws_s3_bucket.reports.bucket
}
