// Where the site is. On the website itself everything is relative. In the browser add-on the chat runs from
// the add-on's own pages (so the website can never change its code) and reaches the site by its full address,
// which the add-on's build sets as globalThis.__ZESURO_SITE__.

declare global {
  var __ZESURO_SITE__: string | undefined;
}

export const siteBase = (): string => (typeof globalThis !== "undefined" && globalThis.__ZESURO_SITE__) || "";
/** True inside the browser add-on. */
export const inAddOn = (): boolean => siteBase() !== "";
/** An address on the site: "/api/x" here, "https://site/api/x" in the add-on. */
export const site = (path: string): string => siteBase() + path;
/** The site's origin, for links people will open in a browser. */
export const siteOrigin = (): string => siteBase() || location.origin;
