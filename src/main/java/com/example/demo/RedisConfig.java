package com.example.demo;

import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class RedisConfig {
    @Bean(name = "RedisClient")
    public RedisClient redisClient() {
        return RedisClient.create("redis://localhost:6379/");
    }

    @Bean(name = "StatefulRedisConnection")
    public StatefulRedisConnection<String, String> statefulRedisConnection(
            @Qualifier("RedisClient") RedisClient redisClient) {
        StatefulRedisConnection<String, String> connection = redisClient.connect();
        return connection;
    }

    @Bean
    public RedisCommands<String, String> redisCommands(
            @Qualifier("StatefulRedisConnection") StatefulRedisConnection<String, String> connection) {
        RedisCommands<String, String> redisCommands = connection.sync();
        return redisCommands;
    }
}
