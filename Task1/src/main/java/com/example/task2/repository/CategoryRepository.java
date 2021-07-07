package com.example.task2.repository;

import com.example.task2.entity.Category;
import com.example.task2.payload.CategoryPro;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(path = "category",collectionResourceRel = "list",excerptProjection = CategoryPro.class)
public interface CategoryRepository extends JpaRepository<Category,Integer> {
}
