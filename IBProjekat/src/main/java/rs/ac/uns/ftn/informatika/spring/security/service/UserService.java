package rs.ac.uns.ftn.informatika.spring.security.service;

import java.util.List;

import rs.ac.uns.ftn.informatika.spring.security.model.User;
import rs.ac.uns.ftn.informatika.spring.security.model.UserRequest;

public interface UserService {
    User findById(Long id);
    User findByEmail(String username);
    List<User> findAll ();
	User save(UserRequest userRequest);
}
