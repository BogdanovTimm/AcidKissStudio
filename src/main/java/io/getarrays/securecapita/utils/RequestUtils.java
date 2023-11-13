package io.getarrays.securecapita.utils;

import jakarta.servlet.http.HttpServletRequest;

/**
 * @author Junior RT
 * @version 1.0
 * @license Get Arrays, LLC (https://getarrays.io)
 * @since 3/21/2023
 */
public class RequestUtils {

    public static final String USER_AGENT_HEADER = "user-agent";

    public static final String X_FORWARDED_FOR_HEADER = "X-FORWARDED-FOR";



    public static String getIpAddress(HttpServletRequest request) {
        String ipAddress = "Unknown IP";
        if (request != null) {
            ipAddress = request.getHeader(X_FORWARDED_FOR_HEADER);
            if (ipAddress == null || "".equals(ipAddress)) {
                ipAddress = request.getRemoteAddr();
            }
        }
        return ipAddress;
    }

    /**
     * Gets user's device from HTTP-Request (need to be checked)
     */
    public static String getDevice(HttpServletRequest request) {
        return "Test";
        /*
        UserAgentAnalyzer userAgentAnalyzer = UserAgentAnalyzer.newBuilder ()
                                                               .hideMatcherLoadStats ()
                                                               .withCache (1000)
                                                               .build ();
        UserAgent agent = userAgentAnalyzer.parse (request.getHeader (USER_AGENT_HEADER));
        //return agent.getValue(OPERATING_SYSTEM_NAME) + " - " + agent.getValue(AGENT_NAME) + " - " + agent.getValue(DEVICE_NAME);
        return agent.getValue (AGENT_NAME) + " - " + agent.getValue (DEVICE_NAME);
        */
    }
}
