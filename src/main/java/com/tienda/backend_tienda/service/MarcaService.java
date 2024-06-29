package com.tienda.backend_tienda.service;

import com.tienda.backend_tienda.entity.Marca;
import com.tienda.backend_tienda.repository.MarcaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MarcaService {

    @Autowired
    private MarcaRepository marcaRepository;

    public List<Marca> getAllMarcas() {
        return marcaRepository.findAll();
    }

    public Marca getMarcaById(Long id) {
        return marcaRepository.findById(id).orElse(null);
    }

    public Marca createMarca(Marca marca) {
        return marcaRepository.save(marca);
    }

    public Marca updateMarca(Long id, Marca marcaDetails) {
        Marca marca = marcaRepository.findById(id).orElse(null);
        if (marca != null) {
            marca.setNombre(marcaDetails.getNombre());
            marca.setDescripcion(marcaDetails.getDescripcion());
            return marcaRepository.save(marca);
        }
        return null;
    }

    public void deleteMarca(Long id) {
        marcaRepository.deleteById(id);
    }
}
