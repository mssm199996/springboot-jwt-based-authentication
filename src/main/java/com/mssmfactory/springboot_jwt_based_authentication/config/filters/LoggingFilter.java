package com.mssmfactory.springboot_jwt_based_authentication.config.filters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import java.io.IOException;

public class LoggingFilter implements Filter {

    private Logger logger = LoggerFactory.getLogger(LoggingFilter.class.getName());

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        this.logger.info(servletRequest.toString());
        this.logger.info(servletResponse.toString());

        filterChain.doFilter(servletRequest, servletResponse);
    }
}
