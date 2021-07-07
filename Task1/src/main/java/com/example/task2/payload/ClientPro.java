package com.example.task2.payload;

import com.example.task2.entity.Client;
import org.springframework.data.rest.core.config.Projection;

@Projection(types = Client.class)
public interface ClientPro {
    Integer getId();
    String getFirstName();
    String getLastName();
    String getAddress();
    String getPhoneNumber();
    String getEmail();
    double getLon();
    double getLat();
}
