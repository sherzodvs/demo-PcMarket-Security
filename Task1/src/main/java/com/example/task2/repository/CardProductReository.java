package com.example.task2.repository;

import com.example.task2.entity.CardProduct;
import com.example.task2.payload.CardProductPro;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(path = "cardProduct", excerptProjection = CardProductPro.class)
public interface CardProductReository extends JpaRepository<CardProduct,Integer> {
}
