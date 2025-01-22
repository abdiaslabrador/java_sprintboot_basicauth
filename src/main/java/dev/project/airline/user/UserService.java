package dev.project.airline.user;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private UserRepository repository;

    public UserService(UserRepository repository) {
        this.repository = repository;
    }

    public User findAll(){
        User users = repository.findByUsername("pepe").get();
        
        return users;
    }
}