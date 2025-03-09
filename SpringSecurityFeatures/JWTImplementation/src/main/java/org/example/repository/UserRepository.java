package org.example.repository;

import org.example.model.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {

    //finds the user by email
    Optional<User> findByEmail(String email);

    //finds the user by verification code , just to make sure user is entering the correct code
    Optional<User> findByVerificationCode(String verificationCode);

}
