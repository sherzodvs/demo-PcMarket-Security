package com.example.task2.payload;

import com.example.task2.entity.Payment;
import org.springframework.data.rest.core.config.Projection;

@Projection(types = Payment.class)
public interface PaymentPro {
    Integer getId();
    String getName();
    boolean isActive();
}
