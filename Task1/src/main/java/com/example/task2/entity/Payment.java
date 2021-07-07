package com.example.task2.entity;

import com.example.task2.entity.template.Abs;
import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.persistence.Entity;

@EqualsAndHashCode(callSuper = true)
@Data
@Entity
public class Payment extends Abs {

}
