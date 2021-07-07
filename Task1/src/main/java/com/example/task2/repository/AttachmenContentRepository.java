package com.example.task2.repository;

import com.example.task2.entity.Attachment;
import com.example.task2.entity.AttachmentContent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AttachmenContentRepository extends JpaRepository<AttachmentContent, Integer> {
    AttachmentContent findByAttachment(Attachment attachment);
}
