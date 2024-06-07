package com.example.demo.request;

import com.example.demo.model.Employee;
import com.example.demo.model.Project;
import lombok.Data;

@Data
public class EmployeeProject {

    private Employee employee;
    private Project project;
}
