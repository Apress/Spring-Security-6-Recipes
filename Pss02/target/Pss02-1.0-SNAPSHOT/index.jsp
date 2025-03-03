<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>


<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Spring Security 6 authentication example!</title>
</head>
<body>
<h2>Welcome to Spring Security 6 authentication example!</h2>

<sec:authorize access="isAuthenticated()">
    <h2>You are an authenticated user:  <sec:authentication property="name"/></h2>
</sec:authorize>

</body>
</html>