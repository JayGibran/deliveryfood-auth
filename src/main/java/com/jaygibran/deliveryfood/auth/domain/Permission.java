package com.jaygibran.deliveryfood.auth.domain;

import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Data
@Entity
public class Permission {

    @EqualsAndHashCode.Include
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String description;
}
