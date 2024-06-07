package com.example.demo.service;

import com.example.demo.model.Employee;
import com.example.demo.repository.EmployeeRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class EmployeeService {

    private final EmployeeRepository employeeRepository;

    public EmployeeService(EmployeeRepository employeeRepository) {
        this.employeeRepository = employeeRepository;
    }

    public Employee findById(Long id){
        return employeeRepository.findById(id).get();
    }

    public List<Employee> get(){
        return employeeRepository.findAll();
    }

    public void save(Employee employee){
        employeeRepository.save(employee);
    }

    public Employee findByEmail(String email){
        return employeeRepository.findByEmail(email);
    }
}
