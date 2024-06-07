package com.example.demo.controller.api.v1;

import com.example.demo.auth.AuthenticatedEmployee;
import com.example.demo.model.Employee;
import com.example.demo.service.EmployeeService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/employees")
public class EmployeeController {

    private final EmployeeService employeeService;

    public EmployeeController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @GetMapping
    public ResponseEntity<?> index(){
        if(checkRoles()){
            List<Employee> employees = employeeService.get();
            return ResponseEntity.ok(employees);
        }
        return ResponseEntity.status(403).body("unauthorized");
    }

    private boolean checkRoles(){
        Employee employee = ((AuthenticatedEmployee) SecurityContextHolder
                .getContext()
                .getAuthentication().getPrincipal()).getEmployee();

        return employee.getPost().toString().equals("ROLE_DEVOPS")
                || employee.getPost().toString().equals("ROLE_TESTER")
                || employee.getPost().toString().equals("ROLE_DEVELOPER");
    }
}
