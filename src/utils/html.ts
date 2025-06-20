/**
 * HTML sanitization utilities for preventing XSS attacks
 */

/**
 * Escapes HTML special characters to prevent XSS attacks
 * @param text - The text to escape
 * @returns The escaped text safe for HTML rendering
 */
export function escapeHtml(text: string): string {
  if (!text) return '';
  
  return text
    .toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Sanitizes HTML attributes to prevent XSS attacks
 * @param attr - The attribute value to sanitize
 * @returns The sanitized attribute value
 */
export function sanitizeAttribute(attr: string): string {
  if (!attr) return '';
  
  // Remove any script-related attributes or javascript: URLs
  const cleaned = attr.toString()
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '');
  
  return escapeHtml(cleaned);
}

/**
 * Validates that a URL is safe for use in HTML
 * @param url - The URL to validate
 * @returns True if the URL is safe, false otherwise
 */
export function isValidUrl(url: string): boolean {
  if (!url) return false;
  
  try {
    const parsed = new URL(url);
    // Only allow http, https, and localhost
    return parsed.protocol === 'https:' || 
           parsed.protocol === 'http:' && 
           (parsed.hostname === 'localhost' || 
            parsed.hostname === '127.0.0.1' || 
            parsed.hostname.endsWith('.localhost'));
  } catch {
    return false;
  }
}