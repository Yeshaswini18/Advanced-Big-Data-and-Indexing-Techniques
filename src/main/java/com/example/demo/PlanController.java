package com.example.demo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.fge.jsonpatch.JsonPatch;
import com.github.fge.jsonpatch.JsonPatchException;
import io.lettuce.core.api.sync.RedisCommands;

import org.everit.json.schema.Schema;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.*;
import java.util.Date;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.*;

@RestController
public class PlanController {
    @Autowired
    RedisCommands<String, String> redisCommands;

    @Autowired
    Schema schema;

    @Autowired
    MessageDigest MessageDigest;

    private static final String ETAG = "ETag";
    private static final String LOGSTASH = "logstash";
    private static final String IF_NONE_MATCH = "if-none-match";
    private static final String AUTHORIZATION = "authorization";
    private Map<String, String> identifierToETags = new HashMap<>();
    private Set<String> tokens = new HashSet<>();

    @GetMapping(path = "/token")
    public ResponseEntity<String> validateIdToken(@RequestHeader(name = "id-token") String idToken) throws IOException, JOSEException {
        JSONObject decodedPayload = getDecodedPayloadFromIdToken(idToken);
        String accessToken;

        int count = (int) idToken.chars().filter(num -> num == '.').count();
        if (count == 2) {
            java.util.Base64.Decoder decoder = java.util.Base64.getUrlDecoder();
            String[] parts = idToken.split("\\.");
            String payloadJson = new String(decoder.decode(parts[1]));
            JSONObject payload = new JSONObject(payloadJson);

            try {
                if (decodedPayload != null && payload.getString("iss").equals(decodedPayload.getString("iss")) &&
                        payload.getString("aud").equals(decodedPayload.getString("aud")) &&
                        String.valueOf(payload.getLong("exp")).equals(decodedPayload.getString("exp"))) {
                    accessToken = generateAccessToken(payload.getString("iss"), payload.getString("sub"));
                    tokens.add(accessToken);
                    return ResponseEntity.ok().body(accessToken);
                }
            } catch (JSONException ex) {
                ex.printStackTrace(); // do nothing since 400 is sent
            }
        }

        return ResponseEntity.badRequest().build();
    }

    @GetMapping(path = "/plan/{id}")
    public ResponseEntity<?> retrieve(@RequestHeader Map<String, String> headers, @PathVariable String id) {
        if (!isAuthorized(headers)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (headers.containsKey(IF_NONE_MATCH) && identifierToETags.containsKey(id) &&
                identifierToETags.get(id).equals(headers.get(IF_NONE_MATCH))) {

            return ResponseEntity.status(HttpStatus.NOT_MODIFIED).eTag(headers.get(IF_NONE_MATCH)).build();
        }

        try {
            String resource = redisCommands.get(id);
            if (resource == null) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.status(HttpStatus.OK).header(ETAG, identifierToETags.get(id)).body(resource);
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping(path = "/plan")
    ResponseEntity<?> send(@RequestHeader Map<String, String> headers, @RequestBody String body) {
        if (!isAuthorized(headers)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        JSONObject jsonObject;
        try {
            jsonObject = bodyToJsonObject(body);
        } catch (JSONException ex) {
            return ResponseEntity.badRequest().build();
        }

        try {
            String key = (String) jsonObject.get("objectId");
            redisCommands.set(key, body);
            redisCommands.lpush(LOGSTASH, body.toString());
            String eTag = generateETag(body);
            identifierToETags.put(key, eTag);
            return ResponseEntity.status(HttpStatus.CREATED).header(ETAG, eTag).build();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }

    @PutMapping(path = "/plan")
    ResponseEntity<?> put(@RequestHeader Map<String, String> headers, @RequestBody String body) {
        if (!isAuthorized(headers)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (!headers.containsKey(IF_NONE_MATCH)) {
            return ResponseEntity.badRequest().build();
        }

        String id = getIdFromETag(headers.get(IF_NONE_MATCH));
        if (id == null) {
            return ResponseEntity.badRequest().build();
        }

        try {
            redisCommands.set(id, body);
            redisCommands.lpush(LOGSTASH, body.toString());
            String eTag = generateETag(body);
            identifierToETags.put(id, eTag);
            return ResponseEntity.status(HttpStatus.NO_CONTENT).header(ETAG, eTag).build();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }

    @DeleteMapping(path = "/plan/{id}")
    ResponseEntity<?> delete(@RequestHeader Map<String, String> headers, @PathVariable String id) {
        if (!isAuthorized(headers)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (!identifierToETags.containsKey(id)) {
            return ResponseEntity.badRequest().build();
        }

        try {
            identifierToETags.remove(id);
            redisCommands.del(id);
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
        return ResponseEntity.ok().build();
    }

    @PatchMapping(path = "/plan", consumes = "application/json-patch+json")
    ResponseEntity<?> patch(@RequestHeader Map<String, String> headers, @RequestBody JsonPatch patch) {
        if (!isAuthorized(headers)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (!headers.containsKey(IF_NONE_MATCH)) {
            return ResponseEntity.badRequest().build();
        }

        String id = getIdFromETag(headers.get(IF_NONE_MATCH));
        if (id == null) {
            return ResponseEntity.badRequest().build();
        }

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String resource = redisCommands.get(id);
            //JsonNode node = objectMapper.readTree(body);
            JsonNode original = objectMapper.readTree(resource);

            //final JsonMergePatch patch = JsonMergePatch.fromJson(node);
            final JsonNode patched = patch.apply(original);
            String json = objectMapper.writeValueAsString(patched);

            redisCommands.set(id, json);
            redisCommands.lpush(LOGSTASH, json);
            String eTag = generateETag(json);
            identifierToETags.put(id, eTag);

            return ResponseEntity.status(HttpStatus.NO_CONTENT).header(ETAG, eTag).build();
        } catch (JsonPatchException | JsonProcessingException ex) {
            ex.printStackTrace();
            return ResponseEntity.badRequest().build();
        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    private JSONObject getDecodedPayloadFromIdToken(String idToken) throws IOException {
        URL getPayLoad = new URL("https://oauth2.googleapis.com/tokeninfo?id_token=" + idToken);
        HttpURLConnection connection = (HttpURLConnection) getPayLoad.openConnection();
        String readline;
        connection.setRequestMethod("GET");
        int responseCode = connection.getResponseCode();

        if (responseCode != (HttpURLConnection.HTTP_OK)) {
            return new JSONObject();
        }

        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder response = new StringBuilder();
        while ((readline = in.readLine()) != null) {
            response.append(readline);
        }

        in.close();
        String payloadJSON = response.toString();
        return new JSONObject(payloadJSON);
    }

    private boolean isAuthorized(Map<String, String> headers) {
        if (headers.containsKey(AUTHORIZATION)) {
            String tokenToBeCompared = headers.get(AUTHORIZATION).substring(7);
            return tokens.contains(tokenToBeCompared);
        }
        return false;
    }

    private String generateAccessToken(String issuer, String subject) throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        JWSSigner signer = new RSASSASigner(rsaJWK);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(issuer)
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
                claimsSet);

        signedJWT.sign(signer);

        String s = signedJWT.serialize();
        return s;
    }

    private String generateETag(String body) {
        byte[] messageDigest = MessageDigest.digest(body.getBytes());
        BigInteger no = new BigInteger(1, messageDigest);
        String hashtext = no.toString(16);
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        return Base64.getEncoder().encodeToString(hashtext.getBytes());
    }

    private JSONObject bodyToJsonObject(String body) throws JSONException {
        JSONObject jsonObject;
        try {
            jsonObject = new JSONObject(body);
            schema.validate(jsonObject);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new JSONException(ex);
        }

        return jsonObject;
    }

    private String getIdFromETag(String eTag) {
        for (Map.Entry<String, String> entry : identifierToETags.entrySet()) {
            if (entry.getValue().equals(eTag)) {
                return entry.getKey();
            }
        }
        return null;
    }
}
