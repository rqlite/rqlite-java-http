package rqlite;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.annotation.ElementType;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import javax.net.ssl.*;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.module.SimpleModule;

/* Annotation to mark fields for URL query parameters.
   The value element defines the parameter name.
   The omitEmpty flag tells the utility to skip default values. */
@Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(java.lang.annotation.ElementType.FIELD)
@interface UValue {
    String value();
    boolean omitEmpty() default false;
}

/* Read consistency level. */
enum ReadConsistencyLevel {
    UNKNOWN, NONE, WEAK, STRONG, LINEARIZABLE, AUTO;
    @Override
    public String toString() {
        switch (this) {
            case NONE: return "none";
            case WEAK: return "weak";
            case STRONG: return "strong";
            case LINEARIZABLE: return "linearizable";
            case AUTO: return "auto";
            default: return "unknown";
        }
    }
}

/* Utility to build a query string from an options object using reflection. */
class URLUtils {
    public static String makeQueryString(Object options) throws Exception {
        if (options == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        Class<?> clazz = options.getClass();
        for (Field field : clazz.getDeclaredFields()) {
            if (!field.isAnnotationPresent(UValue.class)) continue;
            if (!Modifier.isPublic(field.getModifiers())) {
                field.setAccessible(true);
            }
            UValue annot = field.getAnnotation(UValue.class);
            String key = annot.value();
            Object value = field.get(options);
            if (value == null) continue;
            // Skip default/empty values if requested.
            if (annot.omitEmpty()) {
                if (value instanceof Boolean && !((Boolean) value)) continue;
                if (value instanceof Number && ((Number) value).doubleValue() == 0.0) continue;
                if (value instanceof String && ((String) value).isEmpty()) continue;
                if (value instanceof Duration && ((Duration) value).isZero()) continue;
                if (value instanceof ReadConsistencyLevel && value == ReadConsistencyLevel.UNKNOWN) continue;
            }
            String valueStr = (value instanceof Duration) ? value.toString() : value.toString();
            sb.append(first ? "?" : "&");
            first = false;
            sb.append(URLEncoder.encode(key, "UTF-8"));
            sb.append("=");
            sb.append(URLEncoder.encode(valueStr, "UTF-8"));
        }
        return sb.toString();
    }
}

/* A set of helper methods to create HttpClient instances with various TLS settings. */
class HttpClients {

    public static HttpClient defaultHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public static HttpClient newTLSSClientInsecure() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) { }
                public void checkServerTrusted(X509Certificate[] chain, String authType) { }
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };
        sslContext.init(null, trustAll, new SecureRandom());
        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public static HttpClient newTLSSClient(String caCertPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        byte[] caBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(caCertPath));
        ByteArrayInputStream bis = new ByteArrayInputStream(caBytes);
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(bis);

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("caCert", caCert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public static HttpClient newMutualTLSClient(String clientCertPath, String clientKeyPath, String caCertPath) throws Exception {
        // Loading client cert and key from separate PEM files is not straightforward in Java.
        // Typically one uses a PKCS12 keystore. For now, we throw an exception.
        throw new UnsupportedOperationException("Mutual TLS from separate PEM files is not implemented. Use a PKCS12 keystore instead.");
    }
}

/* The main rqlite client. Methods map closely to your Go client.
   For brevity, each method throws Exception on error. */
public class RqliteClient {
    private HttpClient httpClient;
    private String executeURL;
    private String queryURL;
    private String requestURL;
    private String backupURL;
    private String loadURL;
    private String bootURL;
    private String statusURL;
    private String expvarURL;
    private String nodesURL;
    private String readyURL;

    private String basicAuthUser = "";
    private String basicAuthPass = "";
    private AtomicBoolean promoteErrors = new AtomicBoolean(false);
    private final ObjectMapper objectMapper;

    public RqliteClient(String baseURL, HttpClient client) {
        this.executeURL = baseURL + "/db/execute";
        this.queryURL = baseURL + "/db/query";
        this.requestURL = baseURL + "/db/request";
        this.backupURL = baseURL + "/db/backup";
        this.loadURL = baseURL + "/db/load";
        this.bootURL = baseURL + "/boot";
        this.statusURL = baseURL + "/status";
        this.expvarURL = baseURL + "/debug/vars";
        this.nodesURL = baseURL + "/nodes";
        this.readyURL = baseURL + "/readyz";
        this.httpClient = (client != null) ? client : HttpClients.defaultHttpClient();

        objectMapper = new ObjectMapper();
        SimpleModule module = new SimpleModule();
        module.addSerializer(SQLStatement.class, new SQLStatementSerializer());
        module.addDeserializer(SQLStatement.class, new SQLStatementDeserializer());
        objectMapper.registerModule(module);
    }

    public void setBasicAuth(String username, String password) {
        this.basicAuthUser = username;
        this.basicAuthPass = password;
    }

    public void promoteErrors(boolean b) {
        this.promoteErrors.set(b);
    }

    public ExecuteResponse executeSingle(String statement, Object... args) throws Exception {
        SQLStatement stmt = SQLStatement.newSQLStatement(statement, args);
        SQLStatements stmts = new SQLStatements();
        stmts.add(stmt);
        return execute(stmts, null);
    }

    public ExecuteResponse execute(SQLStatements statements, ExecuteOptions opts) throws Exception {
        byte[] body = objectMapper.writeValueAsBytes(statements);
        String queryParams = (opts != null) ? URLUtils.makeQueryString(opts) : "";
        HttpResponse<byte[]> resp = doJSONPostRequest(executeURL + queryParams, body);
        if (resp.statusCode() != 200) {
            throw new IOException("Unexpected status code: " + resp.statusCode() +
                    ", body: " + new String(resp.body()));
        }
        ExecuteResponse er = objectMapper.readValue(resp.body(), ExecuteResponse.class);
        if (promoteErrors.get() && er.hasError()) {
            throw new Exception("Statement error encountered");
        }
        return er;
    }

    public QueryResponse querySingle(String statement, Object... args) throws Exception {
        SQLStatement stmt = SQLStatement.newSQLStatement(statement, args);
        SQLStatements stmts = new SQLStatements();
        stmts.add(stmt);
        return query(stmts, null);
    }

    public QueryResponse query(SQLStatements statements, QueryOptions opts) throws Exception {
        byte[] body = objectMapper.writeValueAsBytes(statements);
        String queryParams = (opts != null) ? URLUtils.makeQueryString(opts) : "";
        HttpResponse<byte[]> resp = doJSONPostRequest(queryURL + queryParams, body);
        if (resp.statusCode() != 200) {
            throw new IOException("Unexpected status code: " + resp.statusCode() +
                    ", body: " + new String(resp.body()));
        }
        QueryResponse qr = objectMapper.readValue(resp.body(), QueryResponse.class);
        if (promoteErrors.get() && qr.hasError()) {
            throw new Exception("Query error encountered");
        }
        return qr;
    }

    public RequestResponse requestSingle(String statement, Object... args) throws Exception {
        SQLStatement stmt = SQLStatement.newSQLStatement(statement, args);
        SQLStatements stmts = new SQLStatements();
        stmts.add(stmt);
        return request(stmts, null);
    }

    public RequestResponse request(SQLStatements statements, RequestOptions opts) throws Exception {
        byte[] body = objectMapper.writeValueAsBytes(statements);
        String queryParams = (opts != null) ? URLUtils.makeQueryString(opts) : "";
        HttpResponse<byte[]> resp = doJSONPostRequest(requestURL + queryParams, body);
        if (resp.statusCode() != 200) {
            throw new IOException("Unexpected status code: " + resp.statusCode() +
                    ", body: " + new String(resp.body()));
        }
        RequestResponse rr = objectMapper.readValue(resp.body(), RequestResponse.class);
        if (promoteErrors.get() && rr.hasError()) {
            throw new Exception("Request error encountered");
        }
        return rr;
    }

    public InputStream backup(BackupOptions opts) throws Exception {
        String queryParams = (opts != null) ? URLUtils.makeQueryString(opts) : "";
        HttpResponse<InputStream> resp = doGetRequestStream(backupURL + queryParams);
        if (resp.statusCode() != 200) {
            throw new IOException("Unexpected status code: " + resp.statusCode());
        }
        return resp.body();
    }

    public void load(InputStream in, LoadOptions opts) throws Exception {
        String queryParams = (opts != null) ? URLUtils.makeQueryString(opts) : "";
        byte[] first13 = new byte[13];
        if (in.read(first13) != 13) {
            throw new IOException("Unable to read first 13 bytes");
        }
        InputStream combined = new SequenceInputStream(new ByteArrayInputStream(first13), in);
        if (validSQLiteData(first13)) {
            doOctetStreamPostRequest(loadURL + queryParams, combined);
        } else {
            doPlainPostRequest(loadURL + queryParams, combined);
        }
    }

    public void boot(InputStream in) throws Exception {
        doOctetStreamPostRequest(bootURL, in);
    }

    public JsonNode status() throws Exception {
        HttpResponse<byte[]> resp = doGetRequestBytes(statusURL);
        if (resp.statusCode() != 200) {
            throw new IOException("Unexpected status code: " + resp.statusCode());
        }
        return objectMapper.readTree(resp.body());
    }

    public JsonNode expvar() throws Exception {
        HttpResponse<byte[]> resp = doGetRequestBytes(expvarURL);
        if (resp.statusCode() != 200) {
            throw new IOException("Unexpected status code: " + resp.statusCode());
        }
        return objectMapper.readTree(resp.body());
    }

    public JsonNode nodes() throws Exception {
        HttpResponse<byte[]> resp = doGetRequestBytes(nodesURL);
        if (resp.statusCode() != 200) {
            throw new IOException("Unexpected status code: " + resp.statusCode());
        }
        return objectMapper.readTree(resp.body());
    }

    public InputStream ready() throws Exception {
        HttpResponse<InputStream> resp = doGetRequest(readyURL);
        return resp.body();
    }

    public void close() {
        // Nothing to close (HttpClient is designed to be reused)
    }

    private HttpResponse<byte[]> doJSONPostRequest(String url, byte[] body) throws Exception {
        return doRequest("POST", url, "application/json", body);
    }

    private HttpResponse<byte[]> doOctetStreamPostRequest(String url, InputStream bodyStream) throws Exception {
        byte[] body = bodyStream.readAllBytes();
        return doRequest("POST", url, "application/octet-stream", body);
    }

    private HttpResponse<byte[]> doPlainPostRequest(String url, InputStream bodyStream) throws Exception {
        byte[] body = bodyStream.readAllBytes();
        return doRequest("POST", url, "text/plain", body);
    }

    private HttpResponse<byte[]> doRequest(String method, String url, String contentType, byte[] body) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(5));
        if ("GET".equalsIgnoreCase(method)) {
            builder.GET();
        } else {
            builder.method(method, HttpRequest.BodyPublishers.ofByteArray(body));
        }
        if (contentType != null && !contentType.isEmpty()) {
            builder.header("Content-Type", contentType);
        }
        addBasicAuth(builder);
        HttpRequest req = builder.build();
        return httpClient.send(req, HttpResponse.BodyHandlers.ofByteArray());
    }

    private HttpResponse<InputStream> doGetRequest(String url) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET();
        addBasicAuth(builder);
        HttpRequest req = builder.build();
        return httpClient.send(req, HttpResponse.BodyHandlers.ofInputStream());
    }

    // For endpoints where you want an InputStream (e.g., backup, ready)
    private HttpResponse<InputStream> doGetRequestStream(String url) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET();
        addBasicAuth(builder);
        HttpRequest req = builder.build();
        return httpClient.send(req, HttpResponse.BodyHandlers.ofInputStream());
    }

    // For endpoints where you need the full response as a byte array (for JSON parsing)
    private HttpResponse<byte[]> doGetRequestBytes(String url) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET();
        addBasicAuth(builder);
        HttpRequest req = builder.build();
        return httpClient.send(req, HttpResponse.BodyHandlers.ofByteArray());
    }

    private void addBasicAuth(HttpRequest.Builder builder) {
        if (!basicAuthUser.isEmpty() || !basicAuthPass.isEmpty()) {
            String auth = basicAuthUser + ":" + basicAuthPass;
            String encoded = Base64.getEncoder().encodeToString(auth.getBytes());
            builder.header("Authorization", "Basic " + encoded);
        }
    }

    private boolean validSQLiteData(byte[] b) {
        if (b.length < 13) return false;
        String header = new String(b, 0, 13);
        return header.equals("SQLite format");
    }
}

/* Response types. Fields are annotated for Jackson. */
class ExecuteResponse {
    @JsonProperty("results")
    public List<ExecuteResult> results;
    @JsonProperty("time")
    public double time;
    @JsonProperty("sequence_number")
    public long sequenceNumber;

    public boolean hasError() {
        if (results != null) {
            for (ExecuteResult res : results) {
                if (res.error != null && !res.error.isEmpty()) {
                    return true;
                }
            }
        }
        return false;
    }
}

class ExecuteResult {
    @JsonProperty("last_insert_id")
    public long lastInsertID;
    @JsonProperty("rows_affected")
    public long rowsAffected;
    @JsonProperty("time")
    public double time;
    @JsonProperty("error")
    public String error;
}

class QueryResponse {
    @JsonProperty("results")
    public Object results; // may be List<QueryResult> or List<QueryResultAssoc>
    @JsonProperty("time")
    public double time;

    public boolean hasError() {
        if (results instanceof List<?>) {
            List<?> list = (List<?>) results;
            if (!list.isEmpty()) {
                Object first = list.get(0);
                if (first instanceof QueryResult) {
                    for (Object o : list) {
                        QueryResult qr = (QueryResult) o;
                        if (qr.error != null && !qr.error.isEmpty()) {
                            return true;
                        }
                    }
                } else if (first instanceof QueryResultAssoc) {
                    for (Object o : list) {
                        QueryResultAssoc qra = (QueryResultAssoc) o;
                        if (qra.error != null && !qra.error.isEmpty()) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
}

class QueryResult {
    @JsonProperty("columns")
    public List<String> columns;
    @JsonProperty("types")
    public List<String> types;
    @JsonProperty("values")
    public List<List<Object>> values;
    @JsonProperty("time")
    public double time;
    @JsonProperty("error")
    public String error;
}

class QueryResultAssoc {
    @JsonProperty("types")
    public Map<String, String> types;
    @JsonProperty("rows")
    public List<Map<String, Object>> rows;
    @JsonProperty("time")
    public double time;
    @JsonProperty("error")
    public String error;
}

class RequestResponse {
    @JsonProperty("results")
    public Object results; // may be List<RequestResult> or List<RequestResultAssoc>
    @JsonProperty("time")
    public double time;

    public boolean hasError() {
        if (results instanceof List<?>) {
            List<?> list = (List<?>) results;
            if (!list.isEmpty()) {
                Object first = list.get(0);
                if (first instanceof RequestResult) {
                    for (Object o : list) {
                        RequestResult rr = (RequestResult) o;
                        if (rr.error != null && !rr.error.isEmpty()) {
                            return true;
                        }
                    }
                } else if (first instanceof RequestResultAssoc) {
                    for (Object o : list) {
                        RequestResultAssoc rra = (RequestResultAssoc) o;
                        if (rra.error != null && !rra.error.isEmpty()) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
}

class RequestResult {
    @JsonProperty("columns")
    public List<String> columns;
    @JsonProperty("types")
    public List<String> types;
    @JsonProperty("values")
    public List<List<Object>> values;
    @JsonProperty("last_insert_id")
    public Long lastInsertID;
    @JsonProperty("rows_affected")
    public Long rowsAffected;
    @JsonProperty("error")
    public String error;
    @JsonProperty("time")
    public double time;
}

class RequestResultAssoc {
    @JsonProperty("types")
    public Map<String, String> types;
    @JsonProperty("rows")
    public List<Map<String, Object>> rows;
    @JsonProperty("last_insert_id")
    public Long lastInsertID;
    @JsonProperty("rows_affected")
    public Long rowsAffected;
    @JsonProperty("error")
    public String error;
    @JsonProperty("time")
    public double time;
}

/* SQL statement types. */
class SQLStatement {
    public String sql;
    public List<Object> positionalParams;
    public Map<String, Object> namedParams;

    public SQLStatement() { }

    public SQLStatement(String sql) {
        this.sql = sql;
    }

    public static SQLStatement newSQLStatement(String stmt, Object... args) {
        SQLStatement s = new SQLStatement(stmt);
        if (args.length == 0) {
            return s;
        }
        if (args.length == 1 && args[0] instanceof Map) {
            s.namedParams = (Map<String, Object>) args[0];
        } else {
            s.positionalParams = Arrays.asList(args);
        }
        return s;
    }
}

/* SQLStatements is simply a list of SQLStatement. */
class SQLStatements extends ArrayList<SQLStatement> { }

/* Custom serializer: if parameters exist, output an array [sql, params…]; otherwise a string. */
class SQLStatementSerializer extends JsonSerializer<SQLStatement> {
    @Override
    public void serialize(SQLStatement s, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        if (s.namedParams != null && !s.namedParams.isEmpty()) {
            gen.writeStartArray();
            gen.writeString(s.sql);
            gen.writeObject(s.namedParams);
            gen.writeEndArray();
        } else if (s.positionalParams != null && !s.positionalParams.isEmpty()) {
            gen.writeStartArray();
            gen.writeString(s.sql);
            for (Object param : s.positionalParams) {
                gen.writeObject(param);
            }
            gen.writeEndArray();
        } else {
            gen.writeString(s.sql);
        }
    }
}

/* Custom deserializer for SQLStatement. */
class SQLStatementDeserializer extends JsonDeserializer<SQLStatement> {
    @Override
    public SQLStatement deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonToken token = p.currentToken();
        SQLStatement stmt = new SQLStatement();
        if (token == JsonToken.VALUE_STRING) {
            stmt.sql = p.getValueAsString();
            return stmt;
        } else if (token == JsonToken.START_ARRAY) {
            List<Object> list = p.readValueAs(List.class);
            if (!list.isEmpty()) {
                stmt.sql = list.get(0).toString();
                if (list.size() > 1) {
                    Object second = list.get(1);
                    if (second instanceof Map) {
                        stmt.namedParams = (Map<String, Object>) second;
                    } else {
                        stmt.positionalParams = list.subList(1, list.size());
                    }
                }
            }
            return stmt;
        }
        throw new IOException("Unexpected JSON token for SQLStatement: " + token);
    }
}

/* Options classes. Their fields are annotated so that URLUtils.makeQueryString
   will convert them into URL query parameters. */
class BackupOptions {
    @UValue(value = "fmt", omitEmpty = true)
    public String format;
    @UValue(value = "vacuum", omitEmpty = true)
    public boolean vacuum;
    @UValue(value = "compress", omitEmpty = true)
    public boolean compress;
    @UValue(value = "noleader", omitEmpty = true)
    public boolean noLeader;
    @UValue(value = "redirect", omitEmpty = true)
    public boolean redirect;
}

class LoadOptions {
    @UValue(value = "redirect", omitEmpty = true)
    public boolean redirect;
}

class ExecuteOptions {
    @UValue(value = "transaction", omitEmpty = true)
    public boolean transaction;
    @UValue(value = "pretty", omitEmpty = true)
    public boolean pretty;
    @UValue(value = "timings", omitEmpty = true)
    public boolean timings;
    @UValue(value = "queue", omitEmpty = true)
    public boolean queue;
    @UValue(value = "wait", omitEmpty = true)
    public boolean wait;
    @UValue(value = "timeout", omitEmpty = true)
    public Duration timeout;
}

class QueryOptions {
    @UValue(value = "timeout", omitEmpty = true)
    public Duration timeout;
    @UValue(value = "pretty", omitEmpty = true)
    public boolean pretty;
    @UValue(value = "timings", omitEmpty = true)
    public boolean timings;
    @UValue(value = "associative", omitEmpty = true)
    public boolean associative;
    @UValue(value = "blob_array", omitEmpty = true)
    public boolean blobAsArray;
    @UValue(value = "level", omitEmpty = true)
    public ReadConsistencyLevel level;
    @UValue(value = "linearizable_timeout", omitEmpty = true)
    public Duration linearizableTimeout;
    @UValue(value = "freshness", omitEmpty = true)
    public Duration freshness;
    @UValue(value = "freshness_strict", omitEmpty = true)
    public boolean freshnessStrict;
}

class RequestOptions {
    @UValue(value = "transaction", omitEmpty = true)
    public boolean transaction;
    @UValue(value = "timeout", omitEmpty = true)
    public Duration timeout;
    @UValue(value = "pretty", omitEmpty = true)
    public boolean pretty;
    @UValue(value = "timings", omitEmpty = true)
    public boolean timings;
    @UValue(value = "associative", omitEmpty = true)
    public boolean associative;
    @UValue(value = "blob_array", omitEmpty = true)
    public boolean blobAsArray;
    @UValue(value = "level", omitEmpty = true)
    public ReadConsistencyLevel level;
    @UValue(value = "linearizable_timeout", omitEmpty = true)
    public String linearizableTimeout;
    @UValue(value = "freshness", omitEmpty = true)
    public String freshness;
    @UValue(value = "freshness_strict", omitEmpty = true)
    public boolean freshnessStrict;
}

class NodeOptions {
    @UValue(value = "timeout", omitEmpty = true)
    public Duration timeout;
    @UValue(value = "pretty", omitEmpty = true)
    public boolean pretty;
    @UValue(value = "non_voters", omitEmpty = true)
    public boolean nonVoters;
    @UValue(value = "ver", omitEmpty = true)
    public String version;
}

