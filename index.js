exports.handler = async (event) => {
  let response = event.Records[0].cf.response;
  let request = event.Records[0].cf.request;
  let headers = response.headers;
  const host = request.headers.host[0].value;
  let domainAdmin = 'admin.jelpit'

  //Set HTTP security headers
  headers['x-content-type-options'] = [{key: 'X-Content-Type-Options', value: 'nosniff'}];
  headers['x-frame-options'] = [{key: 'X-Frame-Options', value: 'SAMEORIGIN'}];
  headers['permissions-policy'] = [{key: 'Permissions-Policy', value: "geolocation=*"}];
  headers['X-XSS-Protection'] = [{ key: 'X-XSS-Protection', value: '1; mode=block' }];
  headers['strict-transport-security'] = [{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' }];
  headers['referrer-policy'] = [{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }];
  headers['Content-Security-Policy'] = [{ key: 'Content-Security-Policy', value: "frame-ancestors 'self'; font-src 'self' blob: data: https://fonts.googleapis.com https://fonts.gstatic.com https://kit.fontawesome.com https://ka-p.fontawesome.com https: ; form-action 'self' connect.facebook.net www.facebook.com ; base-uri 'self'" }];
  
  if (!host.includes(domainAdmin)) {
    headers['set-cookie'] = [{
        key: 'Set-Cookie',
        value: 'HttpOnly; Secure; SameSite=None;'
    }];
  }

  // Return the response to viewers
  return response;
}
