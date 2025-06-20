import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TemplateRenderer } from '../TemplateRenderer.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';

describe('TemplateRenderer', () => {
  let renderer: TemplateRenderer;
  let tempDir: string;

  beforeEach(() => {
    // Create a temporary directory for test templates
    tempDir = join(process.cwd(), 'test-templates');
    try {
      mkdirSync(tempDir, { recursive: true });
    } catch (error) {
      // Directory might already exist
    }

    // Create test templates
    writeFileSync(join(tempDir, 'simple.html'), `
<!DOCTYPE html>
<html>
<head><title>{{TITLE}}</title></head>
<body>
  <h1>{{HEADING}}</h1>
  <p>{{CONTENT}}</p>
</body>
</html>
    `);

    writeFileSync(join(tempDir, 'conditional.html'), `
<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
  <h1>{{TITLE}}</h1>
  {{#if SHOW_MESSAGE}}
  <p>{{MESSAGE}}</p>
  {{/if}}
  {{#if SHOW_ERROR}}
  <div class="error">{{ERROR}}</div>
  {{/if}}
</body>
</html>
    `);

    writeFileSync(join(tempDir, 'nested-conditional.html'), `
<!DOCTYPE html>
<html>
<body>
  {{#if USER}}
  <div>Hello {{USER}}</div>
  {{#if ADMIN}}
  <div>Admin panel: {{ADMIN_MESSAGE}}</div>
  {{/if}}
  {{/if}}
</body>
</html>
    `);

    // Create renderer that uses our test directory
    renderer = new (class extends TemplateRenderer {
      constructor() {
        super();
        (this as any).templateDir = tempDir;
      }
    })();
  });

  afterEach(() => {
    // Clean up test templates
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  describe('Basic Template Rendering', () => {
    it('should render simple template with variables', () => {
      const result = renderer.render('simple', {
        TITLE: 'Test Title',
        HEADING: 'Welcome',
        CONTENT: 'This is test content',
      });

      expect(result).toContain('<title>Test Title</title>');
      expect(result).toContain('<h1>Welcome</h1>');
      expect(result).toContain('<p>This is test content</p>');
    });

    it('should handle missing variables by replacing with empty string', () => {
      const result = renderer.render('simple', {
        TITLE: 'Test Title',
        // HEADING and CONTENT are missing
      });

      expect(result).toContain('<title>Test Title</title>');
      expect(result).toContain('<h1></h1>');
      expect(result).toContain('<p></p>');
    });

    it('should handle undefined variables', () => {
      const result = renderer.render('simple', {
        TITLE: 'Test Title',
        HEADING: undefined,
        CONTENT: 'Content here',
      });

      expect(result).toContain('<title>Test Title</title>');
      expect(result).toContain('<h1></h1>');
      expect(result).toContain('<p>Content here</p>');
    });
  });

  describe('HTML Sanitization', () => {
    it('should escape HTML special characters in variables', () => {
      const result = renderer.render('simple', {
        TITLE: '<script>alert("xss")</script>',
        HEADING: 'Safe & Sound',
        CONTENT: '"Quotes" & \'apostrophes\'',
      });

      expect(result).toContain('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
      expect(result).toContain('Safe &amp; Sound');
      expect(result).toContain('&quot;Quotes&quot; &amp; &#39;apostrophes&#39;');
      expect(result).not.toContain('<script>alert("xss")</script>');
    });

    it('should prevent XSS injection attempts', () => {
      const maliciousPayloads = [
        '<img src=x onerror=alert(1)>',
        '<script>document.location="http://evil.com"</script>',
        '"><script>alert(document.cookie)</script>',
        'javascript:alert(1)',
        '<iframe src="javascript:alert(1)"></iframe>',
      ];

      maliciousPayloads.forEach(payload => {
        const result = renderer.render('simple', {
          TITLE: 'Test',
          HEADING: payload,
          CONTENT: 'Safe content',
        });

        expect(result).not.toContain('<script>');
        expect(result).not.toContain('<img src=x onerror=');
        expect(result).not.toContain('<iframe');
        expect(result).not.toContain('javascript:');
        expect(result).toContain('&lt;');
        expect(result).toContain('&gt;');
      });
    });
  });

  describe('Conditional Rendering', () => {
    it('should show content when condition is true', () => {
      const result = renderer.render('conditional', {
        TITLE: 'Test Page',
        SHOW_MESSAGE: 'true',
        MESSAGE: 'Hello World',
      });

      expect(result).toContain('<h1>Test Page</h1>');
      expect(result).toContain('<p>Hello World</p>');
      expect(result).not.toContain('{{#if SHOW_MESSAGE}}');
      expect(result).not.toContain('{{/if}}');
    });

    it('should hide content when condition is false or empty', () => {
      const result = renderer.render('conditional', {
        TITLE: 'Test Page',
        SHOW_MESSAGE: '',
        MESSAGE: 'This should not appear',
      });

      expect(result).toContain('<h1>Test Page</h1>');
      expect(result).not.toContain('<p>This should not appear</p>');
      expect(result).not.toContain('{{#if SHOW_MESSAGE}}');
    });

    it('should hide content when condition is undefined', () => {
      const result = renderer.render('conditional', {
        TITLE: 'Test Page',
        MESSAGE: 'This should not appear',
      });

      expect(result).toContain('<h1>Test Page</h1>');
      expect(result).not.toContain('<p>This should not appear</p>');
    });

    it('should handle multiple conditionals independently', () => {
      const result = renderer.render('conditional', {
        TITLE: 'Test Page',
        SHOW_MESSAGE: 'yes',
        MESSAGE: 'Success message',
        SHOW_ERROR: 'true',
        ERROR: 'Error occurred',
      });

      expect(result).toContain('<p>Success message</p>');
      expect(result).toContain('<div class="error">Error occurred</div>');
    });

    it('should handle nested conditionals', () => {
      const result = renderer.render('nested-conditional', {
        USER: 'John Doe',
        ADMIN: 'true',
        ADMIN_MESSAGE: 'Welcome admin',
      });

      expect(result).toContain('<div>Hello John Doe</div>');
      expect(result).toContain('<div>Admin panel: Welcome admin</div>');
    });

    it('should handle nested conditionals with outer condition false', () => {
      const result = renderer.render('nested-conditional', {
        USER: '', // Outer condition false
        ADMIN: 'true',
        ADMIN_MESSAGE: 'This should not appear',
      });

      expect(result).not.toContain('Hello');
      expect(result).not.toContain('Admin panel');
      expect(result).not.toContain('This should not appear');
    });

    it('should handle nested conditionals with inner condition false', () => {
      const result = renderer.render('nested-conditional', {
        USER: 'Jane Doe',
        ADMIN: '', // Inner condition false
        ADMIN_MESSAGE: 'This should not appear',
      });

      expect(result).toContain('<div>Hello Jane Doe</div>');
      expect(result).not.toContain('Admin panel');
      expect(result).not.toContain('This should not appear');
    });
  });

  describe('Error Handling', () => {
    it('should throw error for non-existent template', () => {
      expect(() => {
        renderer.render('non-existent', {});
      }).toThrow('Failed to load template \'non-existent\'');
    });

    it('should handle malformed template gracefully', () => {
      writeFileSync(join(tempDir, 'malformed.html'), `
<!DOCTYPE html>
<html>
<body>
  {{#if UNCLOSED_CONDITION}}
  <div>This condition is never closed
</body>
</html>
      `);

      // Should not throw, but the condition won't be processed
      const result = renderer.render('malformed', {
        UNCLOSED_CONDITION: 'true',
      });

      expect(result).toContain('{{#if UNCLOSED_CONDITION}}');
    });
  });

  describe('Caching', () => {
    it('should cache templates after first load', () => {
      // First render
      const result1 = renderer.render('simple', {
        TITLE: 'First',
        HEADING: 'Test',
        CONTENT: 'Content',
      });

      // Modify the template file
      writeFileSync(join(tempDir, 'simple.html'), `
<!DOCTYPE html>
<html>
<head><title>MODIFIED {{TITLE}}</title></head>
<body><h1>MODIFIED {{HEADING}}</h1></body>
</html>
      `);

      // Second render should use cached version
      const result2 = renderer.render('simple', {
        TITLE: 'Second',
        HEADING: 'Test2',
        CONTENT: 'Content2',
      });

      expect(result1).toContain('<title>First</title>');
      expect(result2).toContain('<title>Second</title>');
      expect(result2).not.toContain('MODIFIED');
    });

    it('should support cache clearing', () => {
      // First render
      renderer.render('simple', {
        TITLE: 'Original',
        HEADING: 'Test',
        CONTENT: 'Content',
      });

      // Modify template and clear cache
      writeFileSync(join(tempDir, 'simple.html'), `
<!DOCTYPE html>
<html>
<head><title>MODIFIED {{TITLE}}</title></head>
<body><h1>MODIFIED {{HEADING}}</h1></body>
</html>
      `);

      renderer.clearCache();

      // Should load the modified template
      const result = renderer.render('simple', {
        TITLE: 'Updated',
        HEADING: 'Test',
        CONTENT: 'Content',
      });

      expect(result).toContain('MODIFIED Updated');
    });
  });

  describe('OAuth Callback Integration', () => {
    beforeEach(() => {
      // Create OAuth-specific test templates
      writeFileSync(join(tempDir, 'oauth-success.html'), `
<!DOCTYPE html>
<html>
<head><title>Authorization Successful</title></head>
<body>
  <h1>Success!</h1>
  <div>Code: {{CODE}}</div>
  {{#if STATE}}
  <div>State: {{STATE}}</div>
  {{/if}}
  <pre>curl -X POST {{TOKEN_ENDPOINT}} -d "code={{CODE}}&redirect_uri={{REDIRECT_URI}}"</pre>
</body>
</html>
      `);

      writeFileSync(join(tempDir, 'oauth-error.html'), `
<!DOCTYPE html>
<html>
<head><title>Authorization Error</title></head>
<body>
  <h1>Error: {{ERROR}}</h1>
  {{#if ERROR_DESCRIPTION}}
  <p>{{ERROR_DESCRIPTION}}</p>
  {{/if}}
</body>
</html>
      `);
    });

    it('should render OAuth success page safely', () => {
      const result = renderer.render('oauth-success', {
        CODE: 'safe_auth_code_123',
        STATE: 'safe_state_xyz',
        TOKEN_ENDPOINT: 'https://example.com/token',
        REDIRECT_URI: 'https://example.com/callback',
      });

      expect(result).toContain('Code: safe_auth_code_123');
      expect(result).toContain('State: safe_state_xyz');
      expect(result).toContain('curl -X POST https://example.com/token');
      expect(result).toContain('redirect_uri=https://example.com/callback');
    });

    it('should sanitize malicious OAuth parameters', () => {
      const result = renderer.render('oauth-success', {
        CODE: '<script>alert("code")</script>',
        STATE: '<img src=x onerror=alert(1)>',
        TOKEN_ENDPOINT: 'javascript:alert(2)',
        REDIRECT_URI: '"><script>alert(3)</script>',
      });

      expect(result).not.toContain('<script>');
      expect(result).not.toContain('<img src=x onerror=');
      expect(result).not.toContain('javascript:alert');
      expect(result).toContain('&lt;script&gt;');
      expect(result).toContain('&lt;img src=x onerror=alert(1)&gt;');
    });

    it('should render OAuth error page safely', () => {
      const result = renderer.render('oauth-error', {
        ERROR: 'access_denied',
        ERROR_DESCRIPTION: 'User denied the request',
      });

      expect(result).toContain('Error: access_denied');
      expect(result).toContain('<p>User denied the request</p>');
    });
  });
});