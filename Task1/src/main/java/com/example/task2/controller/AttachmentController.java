package com.example.task2.controller;


import com.example.task2.entity.Attachment;
import com.example.task2.entity.AttachmentContent;
import com.example.task2.repository.AttachmenContentRepository;
import com.example.task2.repository.AttachmentRepository;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Iterator;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/attachment")
public class AttachmentController {

    @Autowired
    AttachmentRepository attachmentRepository;

    @Autowired
    AttachmenContentRepository attachmenContentRepository;

    @GetMapping("/{id}")
    public HttpEntity<?> get(@PathVariable Integer id, HttpServletResponse response) throws IOException {
        Optional<Attachment> optionalAttachment = attachmentRepository.findById(id);
        if (optionalAttachment.isPresent()){
            Attachment attachment = optionalAttachment.get();
            response.setHeader("Content-Disposition", "attachment; filename=\""+attachment.getOrginalName()+"\"");
            response.setContentType(attachment.getContentType());
            AttachmentContent content = attachmenContentRepository.findByAttachment(attachment);
            FileCopyUtils.copy(content.getBytes(),response.getOutputStream());

        }

        return ResponseEntity.status(200).body("OK");
    }

    @SneakyThrows
    @PostMapping
    public HttpEntity<?> add(MultipartHttpServletRequest multipartHttpServletRequest){
        Iterator<String> fileNames = multipartHttpServletRequest.getFileNames();
        if (fileNames.hasNext()){
            String fileName = fileNames.next();
            MultipartFile file = multipartHttpServletRequest.getFile(fileName);
            Attachment attachment = new Attachment();

            String[] originalFilename = file.getOriginalFilename().split("\\.");
            String name = UUID.randomUUID().toString()+"."+originalFilename[originalFilename.length-1];
            attachment.setName(name);
            attachment.setOrginalName(file.getOriginalFilename());
            attachment.setContentType(file.getContentType());
            attachment.setSize(file.getSize());
            Attachment savedAttachment = attachmentRepository.save(attachment);
            AttachmentContent attachmentContent = new AttachmentContent();
            attachmentContent.setBytes(file.getBytes());
            attachmentContent.setAttachment(savedAttachment);
            attachmenContentRepository.save(attachmentContent);
            return ResponseEntity.status(201).body("OK");
        }
        return ResponseEntity.status(409).body("Error");
    }
}
