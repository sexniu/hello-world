package com.xw.edu.util;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.jasig.cas.client.authentication.GatewayResolver;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.Assertion;
import org.springframework.http.HttpRequest;

import com.xw.edu.listener.SessionContext;

public class MyAuthenticationFilter extends AbstractCasFilter{
	/**
     * The URL to the CAS Server login.
     */
    private String casServerLoginUrl;

    /**
     * Whether to send the renew request or not.
     */
    private boolean renew = false;

    /**
     * Whether to send the gateway request or not.
     */
    private boolean gateway = false;
    
    private GatewayResolver gatewayStorage = new DefaultGatewayResolverImpl();

    protected void initInternal(final FilterConfig filterConfig) throws ServletException {
        if (!isIgnoreInitConfiguration()) {
            super.initInternal(filterConfig);
            setCasServerLoginUrl(getPropertyFromInitParams(filterConfig, "casServerLoginUrl", null));
            log.trace("Loaded CasServerLoginUrl parameter: " + this.casServerLoginUrl);
            setRenew(parseBoolean(getPropertyFromInitParams(filterConfig, "renew", "false")));
            log.trace("Loaded renew parameter: " + this.renew);
            setGateway(parseBoolean(getPropertyFromInitParams(filterConfig, "gateway", "false")));
            log.trace("Loaded gateway parameter: " + this.gateway);

            final String gatewayStorageClass = getPropertyFromInitParams(filterConfig, "gatewayStorageClass", null);

            if (gatewayStorageClass != null) {
                try {
                    this.gatewayStorage = (GatewayResolver) Class.forName(gatewayStorageClass).newInstance();
                } catch (final Exception e) {
                    log.error(e,e);
                    throw new ServletException(e);
                }
            }
        }
    }

    public void init() {
        super.init();
        CommonUtils.assertNotNull(this.casServerLoginUrl, "casServerLoginUrl cannot be null.");
    }

    public final void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        final HttpSession session = request.getSession(false);
        
        String strs="";
  	   	strs=request.getParameter("jsessionid");
  	   	if(strs!=null&& !"".equals(strs)){
  	
  	   		//HttpSession sess = SessionContext.getSession(strs);
  	   		//System.out.println("过滤器session===>"+sess);
  	   		//	Assertion assertion = sess != null ? (Assertion) sess.getAttribute(CONST_CAS_ASSERTION) : null;
  	   		//System.out.println("过滤器Assertion==>"+sess);
  		   filterChain.doFilter(request, response);
           return;
  	    }
       
        
       
        	
      final   Assertion assertion = session != null ? (Assertion) session.getAttribute(CONST_CAS_ASSERTION) : null;

        if (assertion != null) {
            filterChain.doFilter(request, response);
            return;
        }

        final String serviceUrl = constructServiceUrl(request, response);
        final String ticket = CommonUtils.safeGetParameter(request,getArtifactParameterName());
        final boolean wasGatewayed = this.gatewayStorage.hasGatewayedAlready(request, serviceUrl);

        if (CommonUtils.isNotBlank(ticket) || wasGatewayed) {
            filterChain.doFilter(request, response);
            return;
        }

        final String modifiedServiceUrl;

        log.debug("no ticket and no assertion found");
        if (this.gateway) {
            log.debug("setting gateway attribute in session");
            modifiedServiceUrl = this.gatewayStorage.storeGatewayInformation(request, serviceUrl);
        } else {
            modifiedServiceUrl = serviceUrl;
        }

        if (log.isDebugEnabled()) {
            log.debug("Constructed service url: " + modifiedServiceUrl);
        }

        final String urlToRedirectTo = CommonUtils.constructRedirectUrl(this.casServerLoginUrl, getServiceParameterName(), modifiedServiceUrl, this.renew, this.gateway);

        if (log.isDebugEnabled()) {
            log.debug("redirecting to \"" + urlToRedirectTo + "\"");
        }
       
        
	
      
     /*   //加修改代码
      if(ticket == null && assertion == null){
        	String requestType=request.getHeader("X-Requested-With");
        	if(null != requestType && requestType.equals("XMLHttpRequest")){
        		HttpSession sessiuon=request.getSession();
        		System.out.println("---fifter---id==>"+sessiuon.getId());
        		servletRequest.setAttribute("jsessionid", sessiuon.getId());
				filterChain.doFilter(servletRequest, response);
				return;	
        		//------------
        		HttpRequest req = (HttpRequest)servletRequest;
        		String url = req.getURI().toString();
        		System.out.println("原请求URL为====="+url);
        		HttpServletRequest hsr=(HttpServletRequest)req;
        		
        		if(!url.contains("jsessionid")){
        			System.out.println("原请求URL为====="+url);
            		String newUrl = url+"?jsessionid="+sessiuon.getId();
            		System.out.println("新请求URL为====="+url);
            		
            		
            		Map<String,String[]> keys= request.getParameterMap();
            		Set set=keys.keySet();
            		Iterator<String> iterator=set.iterator();
            		while(iterator.hasNext()){
            			String str=iterator.next();
            			
            			hsr.setAttribute(str,keys.get(str) );
            		}
            		hsr.setAttribute("jsessionid", sessiuon.getId());
            		 filterChain.doFilter(hsr, response);
            		//response.sendRedirect(newUrl);
            		return;
        		}
        		//---------------
        	}
        }*/
        
        response.sendRedirect(urlToRedirectTo);
    }

    public final void setRenew(final boolean renew) {
        this.renew = renew;
    }

    public final void setGateway(final boolean gateway) {
        this.gateway = gateway;
    }

    public final void setCasServerLoginUrl(final String casServerLoginUrl) {
        this.casServerLoginUrl = casServerLoginUrl;
    }
    
    public final void setGatewayStorage(final GatewayResolver gatewayStorage) {
    	this.gatewayStorage = gatewayStorage;
    }
}
