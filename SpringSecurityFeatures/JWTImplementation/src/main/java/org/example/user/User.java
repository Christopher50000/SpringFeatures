package org.example.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder //build object using builder pattern
@NoArgsConstructor // able to create obj without args
@AllArgsConstructor //able to create obj with args
@Entity //entity is a class that is mapped to a database table
@Table(name = "_user_")
public class User {
    @Id
    @GeneratedValue //(strategy = GenerationType.AUTO) automatically generates id // auto generates id seq but auto chooses Sequence for postgres
    private Integer id;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
}
