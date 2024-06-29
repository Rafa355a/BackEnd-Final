package com.tienda.backend_tienda.service;
import com.tienda.backend_tienda.entity.Categoria;
import com.tienda.backend_tienda.repository.CategoriaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
@Service
public class CategoriaService {
    @Autowired
    private CategoriaRepository categoriaRepository;
    public List<Categoria> getAllCategorias() {
        return categoriaRepository.findAll();
    }
    public Categoria getCategoriaById(Long id) {
        return categoriaRepository.findById(id).orElse(null);
    }
    public Categoria createCategoria(Categoria categoria) {
        return categoriaRepository.save(categoria);
    }
    public Categoria updateCategoria(Long id, Categoria categoriaDetails) {
        Categoria categoria = categoriaRepository.findById(id).orElse(null);
        if (categoria != null) {
            categoria.setNombre(categoriaDetails.getNombre());
            categoria.setDescripcion(categoriaDetails.getDescripcion());
            return categoriaRepository.save(categoria);
        }
        return null;
    }
    public void deleteCategoria(Long id) {
        categoriaRepository.deleteById(id);
    }
}
