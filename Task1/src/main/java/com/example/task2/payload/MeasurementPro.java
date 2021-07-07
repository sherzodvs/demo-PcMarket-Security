package com.example.task2.payload;

import com.example.task2.entity.Measurement;
import com.example.task2.entity.Payment;
import org.springframework.data.rest.core.config.Projection;

@Projection(types = Measurement.class)
public interface MeasurementPro {
    Integer getId();
    String getName();
    boolean isActive();
}
