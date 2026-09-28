package com.security.AprendiendoSpringSecurity.repositories;

import com.security.AprendiendoSpringSecurity.models.RoleEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends CrudRepository<RoleEntity, Long> {
}
