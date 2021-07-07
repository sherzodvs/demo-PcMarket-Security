package com.example.task2.payload;

import com.example.task2.entity.Category;
import com.example.task2.entity.Payment;
import org.springframework.data.rest.core.config.Projection;

@Projection(types = CategoryPro.class)
public interface CategoryPro {
    Integer getId();
    String getName();
    boolean isActive();
    Category getParentCategory();
}
