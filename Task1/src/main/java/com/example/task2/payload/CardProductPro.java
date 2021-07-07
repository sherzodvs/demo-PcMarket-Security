package com.example.task2.payload;

import com.example.task2.entity.Card;
import com.example.task2.entity.CardProduct;
import com.example.task2.entity.Product;
import org.springframework.data.rest.core.config.Projection;

@Projection(types = CardProduct.class)
public interface CardProductPro {
    Integer getId();
    Product getProduct();
    Double getAmmount();
    Integer getWarranty();
    Card getCard();
}
