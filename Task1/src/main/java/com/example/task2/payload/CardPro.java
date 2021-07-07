package com.example.task2.payload;

import com.example.task2.entity.Card;
import com.example.task2.entity.Client;
import com.example.task2.entity.Payment;
import com.example.task2.entity.enums.Status;
import org.springframework.data.rest.core.config.Projection;

import java.sql.Date;

@Projection(types = Card.class)
public interface CardPro {
    Integer getId();
    Date getDate();
    String getFuctureNumber();
    Client getClient();
    Payment getPayment();
    Status getStatus();
}
