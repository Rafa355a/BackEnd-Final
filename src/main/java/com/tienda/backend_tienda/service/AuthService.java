package com.tienda.backend_tienda.service;

import com.google.api.client.http.javanet.NetHttpTransport;
import com.tienda.backend_tienda.entity.Usuario;
import com.tienda.backend_tienda.repository.UsuarioRepository;
import com.tienda.backend_tienda.util.JwtUtil;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.sql.Timestamp;

@Service
public class AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public String authenticateUser(String email, String password) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return jwtUtil.generateToken((org.springframework.security.core.userdetails.User) authentication.getPrincipal());
    }

    public String authenticateGoogleUser(String token) throws Exception {
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new JacksonFactory())
                .setAudience(Collections.singletonList("676877569274-73q4b85k0nkvk46j7qrge97de6vm3v5f.apps.googleusercontent.com"))
                .build();

        GoogleIdToken idToken = verifier.verify(token);
        if (idToken != null) {
            GoogleIdToken.Payload payload = idToken.getPayload();

            String email = payload.getEmail();
            Usuario usuario = usuarioRepository.findByEmail(email);

            if (usuario == null) {
                usuario = new Usuario();
                usuario.setEmail(email);
                usuario.setNombre((String) payload.get("name"));
                usuario.setPassword("");  // No password for Google accounts
                usuarioRepository.save(usuario);
            }

            return jwtUtil.generateToken(new org.springframework.security.core.userdetails.User(usuario.getEmail(), "", Collections.emptyList()));
        } else {
            throw new RuntimeException("Invalid ID token.");
        }
    }

    public Usuario registerUser(Usuario usuario) {
        if (usuarioRepository.findByEmail(usuario.getEmail()) != null) {
            throw new RuntimeException("El email ya está registrado");
        }
        usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
        usuario.setFecha(new Timestamp(System.currentTimeMillis()));  // Asignar la fecha actual
        return usuarioRepository.save(usuario);
    }
}
