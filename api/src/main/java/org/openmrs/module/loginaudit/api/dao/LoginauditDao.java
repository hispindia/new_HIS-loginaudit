/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.loginaudit.api.dao;

import java.util.Date;

import org.hibernate.Criteria;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.api.db.DAOException;
import org.openmrs.api.db.hibernate.DbSession;
import org.openmrs.api.db.hibernate.DbSessionFactory;
import org.openmrs.module.loginaudit.LoginUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository("loginaudit.LoginauditDao")
public class LoginauditDao {
	
	@Autowired
	DbSessionFactory sessionFactory;
	
	private DbSession getSession() {
		return sessionFactory.getCurrentSession();
	}
	
	public void saveLoginDetail(Integer userID) throws DAOException {
		
		User user = Context.getUserService().getUser(userID);
		LoginUser loggeduser = new LoginUser();
		loggeduser.setUser(user);
		loggeduser.setStartDateTime(new Date());
		getSession().saveOrUpdate(loggeduser);
		
	}
	
	@Transactional
	public void saveLogoutDetail(Integer userID) throws DAOException {
		User user = Context.getUserService().getUser(userID);
		LoginUser loggeduser = getLastLogin(user);
		if (loggeduser.getEndtDateTime() == null) {
			loggeduser.setEndtDateTime(new Date());
			getSession().save(loggeduser);
		}
		
	}
	
	public LoginUser getLastLogin(User user) {
		Criteria criteria = getSession().createCriteria(LoginUser.class);
		criteria.add(Restrictions.eq("user", user));
		criteria.addOrder(Order.desc("startDateTime")).setMaxResults(1);
		return (LoginUser) criteria.uniqueResult();
		
	}
}
