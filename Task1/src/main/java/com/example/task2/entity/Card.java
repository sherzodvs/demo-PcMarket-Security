package com.example.task2.entity;

import com.example.task2.entity.enums.Status;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.sql.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Card {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String fuctureNumber;

    @ManyToOne
    private Client client;

    @ManyToOne
    private Payment payment;

    private Date date;

    @Enumerated(EnumType.STRING)
    private Status status = Status.DRAFT;
}
