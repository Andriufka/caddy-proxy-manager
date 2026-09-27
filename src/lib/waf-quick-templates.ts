/**
 * Snippets the Quick Templates buttons of the global and per-host WAF forms
 * append to the custom directives. Each must be a line filterCustomDirectives
 * keeps, or the form refuses to save after a click; tests check that.
 *
 * Custom directives come after the OWASP CRS, so a template that switches
 * CRS rules off does it with `ctl:ruleRemoveByTag` in phase 1: the removal
 * holds for the rest of the transaction, including the phase 2 anomaly-score
 * check (949110) that blocks.
 *
 * The path skip matches REQUEST_FILENAME, the path Go has already decoded
 * once, and refuses any path containing "..": the raw REQUEST_URI of
 * /api/../index.php or /api/%2e%2e/index.php starts with /api/, but Caddy
 * forwards it as-is and an upstream that resolves dot-segments serves
 * /index.php. No further decoding transformation is applied, so %252e stays
 * %2e as the upstream sees it. Coraza compiles @rx with (?sm), so the pattern
 * anchors with \A and \z: ^ and $ would also match at a decoded %0a.
 */
export const WAF_QUICK_TEMPLATES: readonly { label: string; snippet: string }[] = [
  {
    label: "Allow IP",
    snippet: `SecRule REMOTE_ADDR "@ipMatch 1.2.3.4" "id:9000,phase:1,allow,nolog,msg:'Allow IP'"`,
  },
  {
    label: "Skip OWASP CRS for path",
    snippet: String.raw`SecRule REQUEST_FILENAME "@rx \A/api/(?:[^.]|\.[^.])*\.?\z" "id:9001,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS"`,
  },
  {
    label: "Skip OWASP CRS XSS rules",
    snippet: `SecAction "id:9003,phase:1,pass,nolog,ctl:ruleRemoveByTag=attack-xss"`,
  },
  {
    label: "Block User-Agent",
    snippet: `SecRule REQUEST_HEADERS:User-Agent "@contains badbot" "id:9002,phase:1,deny,status:403,log"`,
  },
];

/**
 * Added to the template ids in the per-host form, so the template rules of a
 * merge-mode host don't reuse the ids of the global ones: the merged handler
 * holds both, and Coraza refuses a duplicate rule id.
 */
export const HOST_TEMPLATE_ID_OFFSET = 100;

const TEMPLATE_ID = /\bid:(\d+)/;
// Every id-like number in the text, commented-out rules and ones the filter
// drops included, so a picked id is free whatever the user changes next.
const ANY_RULE_ID = /\bid[\s\u0085]*:[\s\u0085'"]*(\d+)/gi;

/**
 * `directives` with the template appended, its rule id moved past every id
 * the directives already use so clicking a template twice doesn't repeat it.
 */
export function appendQuickTemplate(
  directives: string,
  template: { snippet: string },
  idOffset = 0
): string {
  const used = new Set([...directives.matchAll(ANY_RULE_ID)].map((match) => Number(match[1])));
  let id = Number(TEMPLATE_ID.exec(template.snippet)?.[1] ?? 0) + idOffset;
  while (used.has(id)) id++;
  const snippet = template.snippet.replace(TEMPLATE_ID, `id:${id}`);
  return directives ? `${directives}\n${snippet}` : snippet;
}
