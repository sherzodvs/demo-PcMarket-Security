package com.example.task2.payload;

import com.example.task2.entity.Measurement;
import com.example.task2.entity.Spesification;
import org.springframework.data.rest.core.config.Projection;

@Projection(types = Spesification.class)
public interface SpecificationDto {
    Integer getId();
    String getName();
    double getAmmount();
    Measurement getMeasurement();
}
