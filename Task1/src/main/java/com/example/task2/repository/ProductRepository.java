package com.example.task2.repository;

import com.example.task2.entity.Product;
import com.example.task2.payload.ProductPro;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(path = "product", excerptProjection = ProductPro.class)
public interface ProductRepository extends JpaRepository<Product, Integer> {
}
