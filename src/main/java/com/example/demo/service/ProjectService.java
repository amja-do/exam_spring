package com.example.demo.service;

import com.example.demo.model.Project;
import com.example.demo.repository.ProjectRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProjectService {

    private final ProjectRepository projectRepository;

    public ProjectService(ProjectRepository projectRepository) {
        this.projectRepository = projectRepository;
    }

    public Project findById(Long id){
        return projectRepository.findById(id).get();
    }

    public List<Project> get(){
        return projectRepository.findAll();
    }
}
