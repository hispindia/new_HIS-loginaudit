/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.loginaudit.web.controller;

import java.io.IOException;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.codehaus.jackson.map.ObjectMapper;
import org.openmrs.api.AdministrationService;
import org.openmrs.api.context.Context;
import org.openmrs.module.loginaudit.api.LoginauditService;
import org.openmrs.module.webservices.rest.SimpleObject;
import org.openmrs.module.webservices.rest.web.ConversionUtil;
import org.openmrs.module.webservices.rest.web.RestConstants;
import org.openmrs.module.webservices.rest.web.api.RestService;
import org.openmrs.module.webservices.rest.web.representation.CustomRepresentation;
import org.openmrs.module.webservices.rest.web.representation.Representation;
import org.openmrs.module.webservices.rest.web.v1_0.controller.MainResourceController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.WebRequest;

/**
 * Controller that lets a client check the status of their session, and log out. (Authenticating is
 * handled through a filter, and may happen through this or any other resource.
 */
@Controller
@RequestMapping(value = "/rest/" + RestConstants.VERSION_1 + "/loginaudit")
public class LoginauditController extends MainResourceController {
	
	public static final String USER_CUSTOM_REP = "(uuid,display,username,systemId,userProperties,person:(uuid),privileges:(uuid,name),roles:(uuid,name))";
	
	@Autowired
	RestService restService;
	
	@Autowired
	LoginauditService exampleService;
	
	public static final String CORS_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
	
	public static final String CORS_ORIGIN = "https://ln3.hispindia.org";
	
	public static final String CORS_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
	
	public static final String CORS_MAX_AGE = "Access-Control-Max-Age";
	
	public static final String CORS_ALLOW_HEADERS = "Access-Control-Allow-Headers";
	
	public static final String CORS_EXPOSE_HEADERS = "Access-Control-Expose-Headers";
	
	public static final String CORS_REQUEST_HEADERS = "Access-Control-Request-Header";
	
	/**
	 * Tells the user their sessionId, and whether or not they are authenticated.
	 * 
	 * @param request
	 * @return
	 * @throws IOException
	 * @should return the session id if the user is authenticated
	 * @should return the session id if the user is not authenticated
	 */
	
	@RequestMapping(method = RequestMethod.GET)
	@ResponseBody
	public void get(WebRequest request, HttpServletRequest req, HttpServletResponse response) throws IOException {
		AdministrationService adminService = Context.getAdministrationService();
		boolean authenticated = Context.isAuthenticated();
		SimpleObject session = new SimpleObject();
		session.add("sessionId", request.getSessionId()).add("authenticated", authenticated);
		if (authenticated) {
			
			session.add("user", ConversionUtil.convertToRepresentation(Context.getAuthenticatedUser(),
			    new CustomRepresentation(USER_CUSTOM_REP)));
			session.add("locale", Context.getLocale());
			session.add("allowedLocales", Context.getAdministrationService().getAllowedLocales());
			session.add("sessionLocation",
			    ConversionUtil.convertToRepresentation(Context.getUserContext().getLocation(), Representation.REF));
			exampleService.saveLoginDetail(Context.getAuthenticatedUser().getUserId());
		}
		
		String permission = adminService.getGlobalProperty("Access-Control-Pemission");
		if (permission.equals("true")) {
			response.addHeader(CORS_ALLOW_CREDENTIALS, "true");
			response.addHeader(CORS_ALLOW_ORIGIN, CORS_ORIGIN);
			response.addHeader("Vary", CORS_ORIGIN);
		}
		
		ServletOutputStream out = response.getOutputStream();
		
		new ObjectMapper().writeValue(out, session);
	}
	
	/**
	 * Logs the client out
	 * 
	 * @should log the client out
	 */
	@RequestMapping(method = RequestMethod.DELETE)
	@ResponseBody
	@ResponseStatus(value = HttpStatus.NO_CONTENT)
	public void delete(HttpServletRequest request, HttpServletResponse response) {
		exampleService.saveLogoutDetail(Context.getAuthenticatedUser().getUserId());
		Context.logout();
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.invalidate();
		}
		
	}
	
}
