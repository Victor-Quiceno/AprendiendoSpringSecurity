package com.security.AprendiendoSpringSecurity.service;

import com.security.AprendiendoSpringSecurity.models.UserEntity;
import com.security.AprendiendoSpringSecurity.repositories.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.stream.Collectors;


// La función de esta clase es buscar en la base de datos los usuarios en base al username, extraemos los roles convirtiéndolos
// en objetos heredados de GrantedAuthorities y los empaquetamos en set. Al final devuelve el username, password, validacioens y roles
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository){
        this.userRepository = userRepository;
    }


    // Este méto-do spring security lo consulta por debajo para asegurarse cuál va a ser el usuario que se va a consultar.
    // Es de dónde va a jalar los usuarios
    // Se necesita retornar un objeto de tipo User para autenticarnos
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Con esto se recupera el usuario de la base de datos
        UserEntity userEntity = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("El usuario" + username + " no existe"));

        Collection<? extends GrantedAuthority> authorities = userEntity.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_".concat(role.getName().name()))) //IMPORTANTE: A ese parámetro se le tiene que poner "ROLE_", ¿por qué? Porque Spring Security así lo lee, y ya, con esto nos ahorramos muchoso problemas.
                .collect(Collectors.toSet());

        // Con esto le estamos diciendo a Spring Security que el usuario que se va a autenticar lo tiene que buscar en la base de datos
        return new User(userEntity.getUsername(),
                        userEntity.getPassword(),
                        true,
                        true,
                        true,
                        true,
                        authorities);
    }
}
