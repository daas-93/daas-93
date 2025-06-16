const index = require("./../index");

const event = {
  Records: [
    {
      cf: {
        response: {
          headers: [],
        },
        request: {
          headers:{
            host:[
              {
                value: "https:://www.test.com"
              }
            ]
          }
        }
      },
    },
  ],
};

describe("Validate index",  () => {
  let mockEvent;

  beforeEach(() => {
    mockEvent = {
      Records: [{
        cf: {
          response: {
            headers: {}
          },
          request: {
            headers: {
              host: [{
                value: 'example.jelpit.com'
              }]
            }
          }
        }
      }]
    };
  });
  test("Validate headers response", async () => {
    const response = await index.handler(event);
    expect(response.headers).not.toStrictEqual([]);
  });

  test("Validate headers response 2", async () => {
    event.Records[0].cf.request.headers.host[0].value = "https:://dev-admin.jelpit.com"
    const response = await index.handler(event);
    expect(response.headers).not.toStrictEqual([]);
  });

  test('should add all security headers to the response', async () => {
    const response = await index.handler(mockEvent);
    
    expect(response.headers['x-content-type-options']).toBeDefined();
    expect(response.headers['x-frame-options']).toBeDefined();
    expect(response.headers['permissions-policy']).toBeDefined();
    expect(response.headers['X-XSS-Protection']).toBeDefined();
    expect(response.headers['strict-transport-security']).toBeDefined();
    expect(response.headers['referrer-policy']).toBeDefined();
    expect(response.headers['Content-Security-Policy']).toBeDefined();
  });

  test('should set correct security header values', async () => {
    const response = await index.handler(mockEvent);
    
    expect(response.headers['x-content-type-options'][0].value).toBe('nosniff');
    expect(response.headers['x-frame-options'][0].value).toBe('SAMEORIGIN');
    expect(response.headers['permissions-policy'][0].value).toBe('geolocation=*');
    expect(response.headers['X-XSS-Protection'][0].value).toBe('1; mode=block');
    expect(response.headers['strict-transport-security'][0].value)
      .toBe('max-age=31536000; includeSubDomains; preload');
    expect(response.headers['referrer-policy'][0].value)
      .toBe('strict-origin-when-cross-origin');
  });
  test('should add set-cookie header for non-admin domains', async () => {
    const response = await index.handler(mockEvent);
    
    expect(response.headers['set-cookie']).toBeDefined();
    expect(response.headers['set-cookie'][0].value)
      .toBe('HttpOnly; Secure; SameSite=None;');
  });

  test('should not add set-cookie header for admin domain', async () => {
    mockEvent.Records[0].cf.request.headers.host[0].value = 'admin.jelpit';
    const response = await index.handler(mockEvent);
    
    expect(response.headers['set-cookie']).toBeUndefined();
  });

  test('should preserve existing headers', async () => {
    mockEvent.Records[0].cf.response.headers = {
      'existing-header': [{
        key: 'Existing-Header',
        value: 'test-value'
      }]
    };
    
    const response = await index.handler(mockEvent);
    
    expect(response.headers['existing-header']).toBeDefined();
    expect(response.headers['existing-header'][0].value).toBe('test-value');
  });
});
