package com.example.task2.repository;

import com.example.task2.entity.Client;
import com.example.task2.payload.ClientPro;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(path = "client",collectionResourceRel = "list", excerptProjection = ClientPro.class)
public interface ClientRepository extends JpaRepository<Client,Integer> {

}

