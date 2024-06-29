package com.tienda.backend_tienda.controller;

import com.tienda.backend_tienda.entity.Usuario;
import com.tienda.backend_tienda.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuth2LoginController {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @GetMapping("/loginSuccess")
    public String getLoginInfo(Authentication authentication) {
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String email = oauth2User.getAttribute("email");
        Usuario usuario = usuarioRepository.findByEmail(email);
        if (usuario == null) {
            usuario = new Usuario();
            usuario.setEmail(email);
            usuario.setNombre(oauth2User.getAttribute("name"));
            usuarioRepository.save(usuario);
        }
        return "Login successful: " + oauth2User.getAttributes();
    }

    @GetMapping("/loginFailure")
    public String loginFailure() {
        return "Login failed";
    }
}
