package org.openmrs.module.loginaudit;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import org.openmrs.User;

@Entity(name = "crudexample.LoginUser")
@Table(name = "login_audit")
public class LoginUser implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue
	@Column(name = "login_audit_id")
	private Integer loginauditID;
	
	//private String name;
	
	@ManyToOne
	@JoinColumn(name = "user_id")
	private User user;
	
	@Basic
	private Date startDateTime;
	
	@Basic
	private Date endtDateTime;
	
	//private String ipAdd;
	
	public LoginUser() {
	}
	
	public Integer getLoginauditID() {
		return loginauditID;
	}
	
	public void setLoginauditID(Integer loginauditID) {
		this.loginauditID = loginauditID;
	}
	
	/*
	 * public String getName() { return name; }
	 * 
	 * public void setName(String name) { this.name = name; }
	 */
	
	public User getUser() {
		return user;
	}
	
	public void setUser(User user) {
		this.user = user;
	}
	
	public Date getStartDateTime() {
		return startDateTime;
	}
	
	public void setStartDateTime(Date startDateTime) {
		this.startDateTime = startDateTime;
	}
	
	public Date getEndtDateTime() {
		return endtDateTime;
	}
	
	public void setEndtDateTime(Date endtDateTime) {
		this.endtDateTime = endtDateTime;
	}
	
	/*
	 * public String getIpAdd() { return ipAdd; }
	 * 
	 * public void setIpAdd(String ipAdd) { this.ipAdd = ipAdd; }
	 */
	
}
