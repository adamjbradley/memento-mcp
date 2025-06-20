import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { escapeHtml } from '../utils/html.js';
import { OAuthCallbackConfig } from './OAuthConfig.js';

/**
 * Simple template renderer with HTML sanitization and configuration support
 */
export class TemplateRenderer {
  private templateCache = new Map<string, string>();
  private readonly templateDir: string;

  constructor(private callbackConfig?: OAuthCallbackConfig) {
    // Get the directory where this file is located
    const currentFile = fileURLToPath(import.meta.url);
    this.templateDir = join(dirname(currentFile), 'templates');
  }

  /**
   * Renders a template with the given variables, sanitizing all inputs
   * @param templateName - Name of the template file (without .html extension)
   * @param variables - Variables to substitute in the template
   * @returns Rendered HTML string
   */
  render(templateName: string, variables: Record<string, string | undefined>): string {
    const template = this.loadTemplate(templateName);
    
    // Merge user variables with callback configuration variables
    const allVariables = {
      ...variables,
      ...this.getConfigVariables(),
    };
    
    return this.substituteVariables(template, allVariables);
  }

  /**
   * Gets template variables from callback configuration
   * @returns Configuration variables for templates
   */
  private getConfigVariables(): Record<string, string | undefined> {
    if (!this.callbackConfig) {
      return {};
    }

    return {
      CUSTOM_CSS_URL: this.callbackConfig.customCssUrl,
      BRANDING_TITLE: this.callbackConfig.brandingTitle,
      BRANDING_LOGO: this.callbackConfig.brandingLogo,
      SUPPORT_EMAIL: this.callbackConfig.supportEmail,
      PRIVACY_POLICY_URL: this.callbackConfig.privacyPolicyUrl,
      TERMS_OF_SERVICE_URL: this.callbackConfig.termsOfServiceUrl,
    };
  }

  /**
   * Loads a template from disk, with caching
   * @param templateName - Name of the template file
   * @returns Template content
   */
  private loadTemplate(templateName: string): string {
    const cacheKey = templateName;
    
    if (this.templateCache.has(cacheKey)) {
      return this.templateCache.get(cacheKey)!;
    }

    const templatePath = join(this.templateDir, `${templateName}.html`);
    
    try {
      const content = readFileSync(templatePath, 'utf-8');
      this.templateCache.set(cacheKey, content);
      return content;
    } catch (error) {
      throw new Error(`Failed to load template '${templateName}': ${error}`);
    }
  }

  /**
   * Substitutes variables in template with sanitized values
   * @param template - Template content
   * @param variables - Variables to substitute
   * @returns Rendered template
   */
  private substituteVariables(template: string, variables: Record<string, string | undefined>): string {
    let result = template;

    // Handle simple variable substitution {{VARIABLE}}
    result = result.replace(/\{\{(\w+)\}\}/g, (match, varName) => {
      const value = variables[varName];
      return value ? escapeHtml(value) : '';
    });

    // Handle conditional blocks {{#if VARIABLE}} ... {{/if}}
    result = result.replace(/\{\{#if (\w+)\}\}([\s\S]*?)\{\{\/if\}\}/g, (match, varName, content) => {
      const value = variables[varName];
      if (value && value.trim() !== '') {
        // Recursively process the content inside the conditional
        return this.substituteVariables(content, variables);
      }
      return '';
    });

    return result;
  }

  /**
   * Clears the template cache (useful for testing or development)
   */
  clearCache(): void {
    this.templateCache.clear();
  }
}