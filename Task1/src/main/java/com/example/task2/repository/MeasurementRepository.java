package com.example.task2.repository;


import com.example.task2.entity.Measurement;
import com.example.task2.payload.MeasurementPro;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(path = "measurement", excerptProjection = MeasurementPro.class)
public interface MeasurementRepository extends JpaRepository<Measurement,Integer> {
}
