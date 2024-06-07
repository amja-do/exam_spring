package com.example.demo.service;

import com.example.demo.auth.AuthenticatedEmployee;
import com.example.demo.model.Employee;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JpaEmployeeUserDetailsService implements UserDetailsService {
    private final EmployeeService employeeService;

    public JpaEmployeeUserDetailsService(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Employee employee = employeeService.findByEmail(username);
        if(employee == null )
            throw new UsernameNotFoundException("not found");
        AuthenticatedEmployee authenticatedEmployee = new AuthenticatedEmployee();
        authenticatedEmployee.setEmployee(employee);
        return authenticatedEmployee;

    }
}
