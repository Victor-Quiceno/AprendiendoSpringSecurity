package com.security.AprendiendoSpringSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

//Indicamos que estamos configurando la seguridad de la aplicación
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Esta es la configuración de seguridad.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        // En Spring Security 6+ (Spring Boot 3+), el estilo clásico con '.and()' fue eliminado.
        // Ahora se usa el estilo Lambda (Customizers) para hacer el código más claro y seguro.
        
        return httpSecurity

                // Como no vamos a trabajar con formularios por ahora, entonces lo desactivamos
                .csrf(config -> config.disable())

                // 1. Configuramos las reglas de autorización para las peticiones HTTP (Acceso a urls y puertos)
                // 'auth' es el objeto que nos permite definir qué URLs son públicas y cuáles privadas
                .authorizeHttpRequests(auth -> auth

                        // Permitimos el acceso total (sin login) al endpoint "/v1/index2"
                        .requestMatchers("/v1/index2", "/hello").permitAll()

                        // Cualquier otra petición diferente a la de arriba, exigirá que el usuario esté autenticado
                        .anyRequest().authenticated()
                )
                // 2. Configuramos el inicio de sesión mediante el formulario por defecto de Spring
                // 'form' es el configurador del formulario de login
                // permitAll() aquí significa que cualquier persona puede ver la pantalla de login
                .formLogin(form -> form
                        .successHandler(successHandler()) //Esto sirve para redirigir una vez se efectuó el login
                        .permitAll())
                        
                // Habilitar la autenticación básica HTTP
                .httpBasic(org.springframework.security.config.Customizer.withDefaults())


                //Esto sirve para controlar el comportamiento de las sesiones
                // Política ALWAYS: Crea la sesión si no existe ninguna y si ya existe, la reutiliza
                // Política IS_REQUIRED: Crea una nueva sesión solo si es necesario, si existe la crea, si no, la reutiliza, la diferencia es que esta es más estricta
                // Política NEVER: No crea ninguna sesión, pero si ya existe una, la utiliza
                //Política STATELESS: No crea ninguna sesión, todas las solicitudes las trabaja independientemente y no guarda ningún dato de sesión
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)                       //ALWAYS - IF_REQUIRED -NEVE -STATELESS
                        .invalidSessionUrl("/login")                                                  //Si la session es inválida, no se pudo crear, u ocurrió algo, redirige al usuario a una url
                        .sessionFixation(fixation -> fixation.migrateSession()) //Lo que pasa cuando la sesión se ve comprometida (migrateSession - newSession - none)
                        .maximumSessions(1)                                                           //Número máximo de sesiones que tiene un usuario (Normalmente solo se deja uno, aunque hay excepciones como aplicaciones multiplataforma, streaming, etc.)
                        .expiredUrl("/login")                                                         //Es a dónde mandamos al usuario cuando la sesión expira
                        .sessionRegistry(sessionRegistry())                                           //Inyectar objeto encargado de administrar todos los registros de la sesion, rastrea los datos del usuario autenticado

                )


                // 3. Construimos el filtro con las configuraciones que definimos
                .build();
    }

    //Esto es lo que ayuda a obtener los datos de la sesión, esto solo toma la implementación.
    @Bean
    public SessionRegistry sessionRegistry(){
        return new SessionRegistryImpl();
    }

    //Esto solo es un metodo de redirección para después de hacer el login (usado más arriba)
    public AuthenticationSuccessHandler successHandler(){
        return (((request, response, authentication) ->
                response.sendRedirect("/v1/session")));
    }

    // Esto es un usuario en memoria para hacer pruebas
    @Bean
    UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("victor")
                .password("123")
                .roles()
                .build());

        return manager;
    }

    // Objeto que se encarga de la administración de la autenticación de los usuarios
    // Necesita un password encoder porque Spring Security necesita que encriptemos las contraseñas
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance(); // Como todavía no vamos a manejar encriptación, retornamos esta instancia
    }

    @Bean
    AuthenticationManager authenticationManager(HttpSecurity httpSecurity, PasswordEncoder passwordEncoder) throws Exception{
        // En la versión nueva, no podemos encadenar to do hasta el .build() directamente
        // porque .passwordEncoder() devuelve un configurador específico (DaoAuthenticationConfigurer)
        // y perdimos el acceso al builder principal.
        
        // Solución: Obtenemos el builder, lo configuramos en una línea y luego lo construimos en otra.
        AuthenticationManagerBuilder builder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
        
        builder.userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder);
                
        return builder.build();
    }

}
