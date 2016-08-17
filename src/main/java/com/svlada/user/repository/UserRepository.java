package com.svlada.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.svlada.entity.User;

/**
 * UserRepository
 * 
 * @author vladimir.stankovic
 *
 * Aug 16, 2016
 */
public interface UserRepository extends JpaRepository<User, Long> {

}
