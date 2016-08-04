package com.svlada.security.model;

/**
 * Enumeration of user Roles.
 * 
 * @author vladimir.stankovic
 *
 * Aug 3, 2016
 */
public enum UserRole {
	ADMIN, INSTRUCTOR, PARTICIPANT, SUPERADMIN;
	
	public String authority() {
		return "ROLE_" + this.name();
	}
}
