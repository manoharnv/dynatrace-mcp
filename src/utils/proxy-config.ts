import { ProxyAgent, setGlobalDispatcher, getGlobalDispatcher } from 'undici';

/**
 * Parse and configure system proxy settings from environment variables.
 * Supports https_proxy, HTTPS_PROXY, http_proxy, HTTP_PROXY, no_proxy, and NO_PROXY.
 *
 * This function should be called early in the application lifecycle to ensure
 * all HTTP requests honor the system proxy settings.
 */
export function configureProxyFromEnvironment(): void {
  // Check for proxy environment variables (case-insensitive)
  const httpsProxy = process.env.https_proxy || process.env.HTTPS_PROXY;
  const httpProxy = process.env.http_proxy || process.env.HTTP_PROXY;
  const noProxy = process.env.no_proxy || process.env.NO_PROXY;

  // Determine which proxy to use (prefer HTTPS proxy for HTTPS requests)
  const proxyUrl = httpsProxy || httpProxy;

  if (!proxyUrl) {
    // No proxy configured, use default dispatcher
    console.error('No proxy configuration found in environment variables.');
    return;
  }

  try {
    console.error(`Configuring proxy from environment: ${proxyUrl}`);

    // Parse no_proxy list if provided
    let noProxyHosts: string[] = [];
    if (noProxy) {
      // Split by comma and trim whitespace
      noProxyHosts = noProxy
        .split(',')
        .map((host) => host.trim())
        .filter((host) => host.length > 0);
      console.error(`No proxy hosts configured: ${noProxyHosts.join(', ')}`);
    }

    // Create ProxyAgent with the configured proxy URL
    const proxyAgent = new ProxyAgent({
      uri: proxyUrl,
      // Note: undici's ProxyAgent doesn't have built-in no_proxy support
      // For production use, you might need to implement custom logic or use a wrapper
    });

    // Set the global dispatcher for undici (affects global fetch)
    setGlobalDispatcher(proxyAgent);

    console.error(`✅ Proxy configured successfully: ${proxyUrl}`);
  } catch (error) {
    console.error(`⚠️ Failed to configure proxy: ${error instanceof Error ? error.message : String(error)}`);
    console.error('Continuing without proxy configuration.');
  }
}

/**
 * Check if a hostname should bypass the proxy based on no_proxy environment variable.
 * This is a helper function for manual proxy bypass checks if needed.
 *
 * @param hostname - The hostname to check
 * @returns true if the hostname should bypass the proxy
 */
export function shouldBypassProxy(hostname: string): boolean {
  const noProxy = process.env.no_proxy || process.env.NO_PROXY;

  if (!noProxy) {
    return false;
  }

  const noProxyHosts = noProxy
    .split(',')
    .map((host) => host.trim())
    .filter((host) => host.length > 0);

  for (const pattern of noProxyHosts) {
    // Handle wildcard patterns
    if (pattern === '*') {
      return true;
    }

    // Handle domain patterns (e.g., .example.com matches *.example.com)
    if (pattern.startsWith('.')) {
      if (hostname.endsWith(pattern) || hostname === pattern.substring(1)) {
        return true;
      }
    }

    // Exact match
    if (hostname === pattern) {
      return true;
    }

    // Handle subdomain wildcards (e.g., *.example.com)
    if (pattern.startsWith('*.')) {
      const domain = pattern.substring(2);
      if (hostname.endsWith('.' + domain) || hostname === domain) {
        return true;
      }
    }
  }

  return false;
}
