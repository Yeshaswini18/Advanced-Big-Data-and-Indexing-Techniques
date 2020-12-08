package com.example.demo;

import org.everit.json.schema.Schema;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Configuration
public class SchemaValidatorConfig {
    @Bean
    public Schema SchemaValidator() {
        ClassLoader classLoader = SchemaValidatorConfig.class.getClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream("templates/json_schema.json");
        JSONObject rawSchema = new JSONObject(new JSONTokener(inputStream));
        Schema schema = SchemaLoader.load(rawSchema);
        return schema;
    }

    @Bean
    public MessageDigest MessageDigest() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md;
    }
}

