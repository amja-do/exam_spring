package com.example.demo.controller;

import com.example.demo.auth.AuthenticatedEmployee;
import com.example.demo.model.Employee;
import com.example.demo.model.Project;
import com.example.demo.request.EmployeeProject;
import com.example.demo.service.EmployeeService;
import com.example.demo.service.ProjectService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequestMapping("/employees")
public class EmployeeController {

    private final EmployeeService employeeService;
    private final ProjectService projectService;

    public EmployeeController(EmployeeService employeeService, ProjectService projectService) {
        this.employeeService = employeeService;
        this.projectService = projectService;
    }

    @GetMapping
    public String index(Model model){
        if(checkManagerOrTechlead()){
            List<Employee> employees = employeeService.get();
            model.addAttribute("employees", employees);
            return "thymleaf/index";
        }
        return "thymleaf/403";
    }

    @GetMapping("/create")
    public String create(Model model){
        if(checkManagerRole()){
            model.addAttribute("request", new EmployeeProject());
            model.addAttribute("employees", employeeService.get());
            model.addAttribute("projects", projectService.get());
            return "jsp/create";
        }
        return "thymleaf/403";
    }

    @PostMapping("/store")
    public String store(Model model, @ModelAttribute EmployeeProject request){
        if(checkManagerRole()) {
            Employee employee = employeeService.findById(request.getEmployee().getId());
            Project project = projectService.findById(request.getProject().getId());
            if (employee != null && project != null) {
                employee.getProjects().add(project);
                employeeService.save(employee);
            }
            List<Employee> employees = employeeService.get();
            model.addAttribute("employees", employees);
            return "thymleaf/index";
        }
        return "thymleaf/403";
    }

    private boolean checkManagerRole(){
        return SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getAuthorities()
                .stream()
                .allMatch(e -> e.getAuthority().equals("ROLE_MANAGER"));
    }

    private boolean checkManagerOrTechlead(){
        Employee employee = ((AuthenticatedEmployee)SecurityContextHolder
                .getContext()
                .getAuthentication().getPrincipal()).getEmployee();

        return employee.getPost().toString().equals("ROLE_MANAGER")
                || employee.getPost().toString().equals("ROLE_TECH_LEAD");
    }
}
