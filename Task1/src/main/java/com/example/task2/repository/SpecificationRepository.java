package com.example.task2.repository;

import com.example.task2.entity.Spesification;
import com.example.task2.payload.SpecificationDto;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(path = "specification", excerptProjection = SpecificationDto.class)
public interface SpecificationRepository extends JpaRepository<Spesification, Integer> {
}
