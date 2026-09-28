package com.security.AprendiendoSpringSecurity.repositories;

import com.security.AprendiendoSpringSecurity.models.UserEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<UserEntity, Long> {

    Optional<UserEntity> findByUsername (String username); // Típico method de JPA para buscar algo

    // Esta es otra manera de trabajar con los repositorios, podemos usar métodos personalizados con una query específica
    @Query("select u from UserEntity u where u.username = ?1") // El ?1 significa que trae el primer valor que encuentre de donde le especificamos
    Optional<UserEntity> getName (String username);

}
