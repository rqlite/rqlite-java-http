package com.example;

import rqlite.RqliteClient;
import com.fasterxml.jackson.databind.JsonNode;

public class App {
    public static void main(String[] args) {
        try {
            // Create a client to connect to rqlite at http://localhost:4001
            RqliteClient client = new RqliteClient("http://localhost:4001", null);
            
            // Retrieve the status
            JsonNode status = client.status();
            
            // Print the status JSON to stdout
            System.out.println("Status: " + status.toString());
            
            // Clean up resources
            client.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

