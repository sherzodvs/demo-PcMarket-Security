package com.example.task2.repository;

import com.example.task2.entity.Card;
import com.example.task2.payload.CardPro;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(path = "card", excerptProjection = CardPro.class)
public interface CardRepository extends JpaRepository<Card,Integer> {

}
