package com.tienda.backend_tienda.controller;

import com.tienda.backend_tienda.entity.Usuario;
import com.tienda.backend_tienda.service.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/usuarios")
public class UsuarioController {

    @Autowired
    private UsuarioService usuarioService;

    @GetMapping
    public List<Usuario> getAllUsuarios() {
        return usuarioService.getAllUsuarios();
    }

    @GetMapping("/{id}")
    public Usuario getUsuarioById(@PathVariable Long id) {
        return usuarioService.getUsuarioById(id);
    }

    @PostMapping
    public Usuario createUsuario(@RequestBody Usuario usuario) {
        return usuarioService.saveUsuario(usuario);
    }

    @PutMapping("/{id}")
    public Usuario updateUsuario(@PathVariable Long id, @RequestBody Usuario usuario) {
        return usuarioService.updateUsuario(id, usuario);
    }

    @DeleteMapping("/{id}")
    public void deleteUsuario(@PathVariable Long id) {
        usuarioService.deleteUsuario(id);
    }

    @GetMapping("/profile")
    public ResponseEntity<Usuario> getUserProfile(@AuthenticationPrincipal UserDetails userDetails) {
        Usuario usuario = usuarioService.findByEmail(userDetails.getUsername()).orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
        return ResponseEntity.ok(usuario);
    }

    @PutMapping("/profile")
    public ResponseEntity<Usuario> updateUserProfile(@RequestBody Usuario updatedUser, @AuthenticationPrincipal UserDetails userDetails) {
        Usuario usuario = usuarioService.findByEmail(userDetails.getUsername()).orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
        usuario.setNombre(updatedUser.getNombre());
        usuario.setDireccion(updatedUser.getDireccion());
        usuario.setTelefono(updatedUser.getTelefono());
        Usuario savedUser = usuarioService.saveUsuario(usuario);
        return ResponseEntity.ok(savedUser);
    }
}
