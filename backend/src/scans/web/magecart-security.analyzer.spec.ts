import { analyzeMagecartAndFormSecurity } from './magecart-security.analyzer';
import { CrawledPage } from './ecommerce-crawler';

describe('magecart-security.analyzer', () => {
  it('detecta scripts externos sin SRI y genera WEB-SRI-MISSING-EXTERNAL-SCRIPT', () => {
    const pages: CrawledPage[] = [
      {
        url: 'https://comercio.com/checkout',
        status: 200,
        html: '<html><body>Checkout</body></html>',
        contentType: 'text/html',
        internalLinks: [],
        forms: [{ action: 'https://comercio.com/pay', method: 'POST', hasCardInput: true, hasPasswordInput: false, inputs: [] }],
        scripts: [
          { src: 'https://cdn.external.com/analytics.js', isExternal: true },
          { src: 'https://cdn.paymentgateway.com/sdk.js', isExternal: true, integrity: 'sha384-abc123456789' },
          { src: 'https://comercio.com/local.js', isExternal: false },
        ],
      },
    ];

    const result = analyzeMagecartAndFormSecurity(pages);
    expect(result.totalExternalScripts).toBe(2);
    expect(result.scriptsMissingSri).toContain('https://cdn.external.com/analytics.js');
    expect(result.scriptsMissingSri).not.toContain('https://cdn.paymentgateway.com/sdk.js');

    const sriFinding = result.findings.find((f) => f.ruleId === 'WEB-SRI-MISSING-EXTERNAL-SCRIPT');
    expect(sriFinding).toBeDefined();
    expect(sriFinding?.title).toContain('Magecart/Skimming - PCI-DSS v4.0');
  });

  it('detecta contenido mixto activo en página HTTPS (WEB-MIXED-CONTENT)', () => {
    const pages: CrawledPage[] = [
      {
        url: 'https://comercio.com/cart',
        status: 200,
        html: `
          <html><body>
            <script src="http://unsecure-cdn.com/bad.js"></script>
            <iframe src="http://tracker.com/frame"></iframe>
          </body></html>
        `,
        contentType: 'text/html',
        internalLinks: [],
        forms: [],
        scripts: [{ src: 'http://unsecure-cdn.com/bad.js', isExternal: true }],
      },
    ];

    const result = analyzeMagecartAndFormSecurity(pages);
    expect(result.mixedContentUrls).toContain('http://unsecure-cdn.com/bad.js');
    expect(result.mixedContentUrls).toContain('http://tracker.com/frame');
    expect(result.findings.some((f) => f.ruleId === 'WEB-MIXED-CONTENT')).toBe(true);
  });

  it('detecta formularios sensibles con envío inseguro vía HTTP (WEB-INSECURE-FORM-ACTION)', () => {
    const pages: CrawledPage[] = [
      {
        url: 'https://comercio.com/login',
        status: 200,
        html: '<html><body>Login</body></html>',
        contentType: 'text/html',
        internalLinks: [],
        forms: [
          {
            action: 'http://auth.comercio.com/submit',
            method: 'POST',
            hasPasswordInput: true,
            hasCardInput: false,
            inputs: [{ type: 'password', name: 'pwd' }],
          },
        ],
        scripts: [],
      },
    ];

    const result = analyzeMagecartAndFormSecurity(pages);
    expect(result.insecureFormsCount).toBe(1);
    const formFinding = result.findings.find((f) => f.ruleId === 'WEB-INSECURE-FORM-ACTION');
    expect(formFinding).toBeDefined();
    expect(formFinding?.evidence?.formAction).toBe('http://auth.comercio.com/submit');
  });
});
