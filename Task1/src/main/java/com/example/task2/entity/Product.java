package com.example.task2.entity;

import com.example.task2.entity.enums.BrandName;
import com.example.task2.entity.enums.ColorName;
import com.example.task2.entity.template.Abs;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@EqualsAndHashCode(callSuper = true)
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Product extends Abs {
    private String description;
    private double price;

    @Enumerated(EnumType.STRING)
    private BrandName brandName;

    @Enumerated(EnumType.STRING)
    private ColorName colorName;

    @ManyToOne
    private Measurement measurement;

    @ManyToOne
    private Category category;

    @OneToOne
    private Attachment photo;

}
