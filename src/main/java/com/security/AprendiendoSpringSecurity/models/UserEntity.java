package com.security.AprendiendoSpringSecurity.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data // Getters y Setters
@AllArgsConstructor
@NoArgsConstructor
@Builder // Lombok implementa el patrón de disñeo builder para construír objetos de la clase
@Entity
@Table (name = "users")
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Validaciones varias
    @Email
    @NotBlank
    @Size(max = 80)
    private String email;

    @NotBlank
    @Size(max = 30)
    private String username;

    @NotBlank
    private String password;

    /* Aquí se establece la relación entre la tabla de usuarios y los roles, es una relación muchos a muchos unidireccional,
    *  también se puede definir como un List, pero se recomienda el Set para no tener elementos duplicados*/

    @ManyToMany(fetch = FetchType.EAGER, targetEntity = RoleEntity.class, cascade = CascadeType.PERSIST)        // Cascade con persist significa que si se elimina un usuario no se eliminen los roles.
    @JoinTable(name = "user_roles",                                                                             // Recordemos que las relaciones muchos a muchos generan tablas intermedias, aquí se define el nombre de dicha tabla
            joinColumns = @JoinColumn(name = "user_id"),                                                        // Aquí se configura cómo se va a llamar la clave foránea de usuario, es decir, esta tabla
            inverseJoinColumns = @JoinColumn(name = "role_id"))                                                 // Este es el nombre de de la columna que contiene la clave foránea de los roles
    private Set<RoleEntity> roles;
}
