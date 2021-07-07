package com.example.task2.repository;

import com.example.task2.entity.Payment;
import com.example.task2.payload.PaymentPro;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.config.Projection;

@RepositoryRestResource(path = "payment",collectionResourceRel = "list",excerptProjection = PaymentPro.class)
public interface PaymentRepository extends JpaRepository<Payment,Integer> {
}
