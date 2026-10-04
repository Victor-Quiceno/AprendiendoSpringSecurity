package com.security.AprendiendoSpringSecurity.security.filters;

import com.security.AprendiendoSpringSecurity.models.UserEntity;
import com.security.AprendiendoSpringSecurity.security.jwt.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

// La clase a la que heredamos es la que nos ayuda a autenticarnos en la aplicación
// Este filtro lo que hace es cuando alguien intenta hacer login, lee las credenciales que envió el usuario y las pasa al
// AuthenticationManager, si este dice que puede pasar, se genera un token y lo devuelve al usuario
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtUtils jwtUtils;

    public JwtAuthenticationFilter(JwtUtils jwtUtils){
        this.jwtUtils = jwtUtils;
    }

    // Esto es lo que pasa cuando el usuario intenta autenticarse en la aplicación
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {


        UserEntity userEntity = null;
        String username = "";
        String password = "";
        try {
            userEntity = new ObjectMapper().readValue(request.getInputStream(), UserEntity.class);
            username = userEntity.getUsername();
            password = userEntity.getPassword();

        }catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Con esto nos autenticamos en la aplicación
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        // El AuthenticationManager es el objeto que se encarga de administrar la autenticación
        return getAuthenticationManager().authenticate(authenticationToken);
    }

    //Este méto-do se ejecuta automáticamente SOLO SI attempAuthentication fue exitoso
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult)
                                            throws IOException, ServletException {


        // Recuperar los detalles del usuario que se ha logeado
        User user = (User) authResult.getPrincipal();
        String token = jwtUtils.generateAccessToken(user.getUsername());

        // El token se pone en el header de la respuesta http, es la forma estándar de enviar tokens
        response.addHeader("Authorization", token);

        Map<String, Object> httpResponse = new HashMap<>();
        httpResponse.put("token", token);
        httpResponse.put("Message", "Autenticacion Correcta");
        httpResponse.put("Username", user.getUsername());

        response.getWriter().write(new ObjectMapper().writeValueAsString(httpResponse));
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().flush();

        super.successfulAuthentication(request, response, chain, authResult);
    }
}
