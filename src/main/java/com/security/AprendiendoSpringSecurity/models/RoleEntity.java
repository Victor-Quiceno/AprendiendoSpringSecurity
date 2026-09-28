package com.security.AprendiendoSpringSecurity.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.AnyDiscriminatorImplicitValues;

@Data // Getters y Setters
@AllArgsConstructor
@NoArgsConstructor
@Builder // Lombok implementa el patrón de disñeo builder para construír objetos de la clase
@Entity
@Table(name = "roles")
public class RoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    private ERole name; // También se puede mediante un String, sin embargo es más profesional usar un ENUM que contenga los roles
}
