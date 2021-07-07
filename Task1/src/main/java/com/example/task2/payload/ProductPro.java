package com.example.task2.payload;

import com.example.task2.entity.Attachment;
import com.example.task2.entity.Category;
import com.example.task2.entity.Measurement;
import com.example.task2.entity.Product;
import com.example.task2.entity.enums.BrandName;
import com.example.task2.entity.enums.ColorName;
import org.springframework.data.rest.core.config.Projection;

@Projection(types = Product.class)
public interface ProductPro {
    Integer getId();
    String getName();
    String getDescription();
    Category getCategory();
    Attachment getPhoto();
    Measurement getMeasurement();
    boolean isActive();
    double getPrice();
    BrandName getBrandName();
    ColorName getColorName();

}
