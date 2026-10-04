package com.security.AprendiendoSpringSecurity.controller;

import com.security.AprendiendoSpringSecurity.controller.request.CreateUserDTO;
import com.security.AprendiendoSpringSecurity.models.ERole;
import com.security.AprendiendoSpringSecurity.models.RoleEntity;
import com.security.AprendiendoSpringSecurity.models.UserEntity;
import com.security.AprendiendoSpringSecurity.repositories.UserRepository;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class PrincipalController {

    // Inyectar dependencia del PasswordEncoder, no podemos enviar las contraseñas a la bd sin encriptación
    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;
    public PrincipalController(PasswordEncoder passwordEncoder,UserRepository userRepository){
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    @GetMapping("/hello")
    public String hello(){

        return "Hello World Not Secured";
    }

    @GetMapping("/helloSecured")
    public String helloSecured(){

        return "Hello World Secured";
    }

    @PostMapping("/createUser")
    public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserDTO createUserDTO){

        // Aquí recibimos un set de Strings con los nombres de los roles y los convertimos en un Set de RoleEntity
        Set<RoleEntity> roles = createUserDTO.getRoles().stream()
                .map(role -> RoleEntity.builder()
                        .name(ERole.valueOf(role))
                        .build())
                .collect(Collectors.toSet());


        /* Esto es gracias a la anotación Builder que nos da Lombok para trabajar con ese patrón de diseño,
           permitiendonos construír el objeto por partes */
        UserEntity userEntity = UserEntity.builder()
                .username(createUserDTO.getUsername())
                .password(passwordEncoder.encode(createUserDTO.getPassword()))      // Encriptamos la contraseña al momento de asignarla al objeto
                .email(createUserDTO.getEmail())
                .roles(roles)
                .build();

        userRepository.save(userEntity);

        return ResponseEntity.ok(userEntity);
    }

    @DeleteMapping("/deleteUser")
    public String deleteUser(@RequestParam String id){

        userRepository.deleteById(Long.parseLong(id));

        return "Se ha borrado el user con id".concat(id);
    }
}
