package com.tienda.backend_tienda.controller;

import com.tienda.backend_tienda.entity.Marca;
import com.tienda.backend_tienda.service.MarcaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/marcas")
public class MarcaController {

    @Autowired
    private MarcaService marcaService;

    @GetMapping
    public List<Marca> getAllMarcas() {
        return marcaService.getAllMarcas();
    }

    @GetMapping("/{id}")
    public Marca getMarcaById(@PathVariable Long id) {
        return marcaService.getMarcaById(id);
    }

    @PostMapping
    public Marca createMarca(@RequestBody Marca marca) {
        return marcaService.createMarca(marca);
    }

    @PutMapping("/{id}")
    public Marca updateMarca(@PathVariable Long id, @RequestBody Marca marca) {
        return marcaService.updateMarca(id, marca);
    }

    @DeleteMapping("/{id}")
    public void deleteMarca(@PathVariable Long id) {
        marcaService.deleteMarca(id);
    }
}
