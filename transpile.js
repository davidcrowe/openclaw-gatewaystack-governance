const fs = require('fs');

function transpileTypeScript(code) {
  // Keep shebang
  const lines = code.split('\n');
  const shebang = lines[0].startsWith('#!') ? lines[0] + '\n' : '';
  if (shebang) {
    code = lines.slice(1).join('\n');
  }

  // Convert import statements (keep them but make them CommonJS)
  code = code.replace(/import\s+\*\s+as\s+(\w+)\s+from\s+["']([^"']+)["']/g, "const $1 = require('$2')");
  code = code.replace(/import\s+(\w+)\s+from\s+["']([^"']+)["']/g, "const $1 = require('$2')");
  code = code.replace(/import\s+\{([^}]+)\}\s+from\s+["']([^"']+)["']/g, "const {$1} = require('$2')");
  code = code.replace(/import\s+type\s+\{[^}]*\}\s+from\s+["'][^"']+["']/g, '');

  // Remove interface declarations - character-by-character brace-counting parser
  let inInterface = false;
  let braceCount = 0;
  let result = [];
  let i = 0;

  while (i < code.length) {
    if (!inInterface && code.substr(i, 9) === 'interface' && !/\w/.test(code[i + 9])) {
      inInterface = true;
      braceCount = 0;
      while (i < code.length && code[i] !== '{') i++;
      if (i < code.length && code[i] === '{') { braceCount = 1; i++; }
    } else if (inInterface) {
      if (code[i] === '{') braceCount++;
      else if (code[i] === '}') {
        braceCount--;
        if (braceCount === 0) {
          inInterface = false;
          i++;
          while (i < code.length && code[i] !== '\n' && code[i] !== ';') i++;
          if (i < code.length && code[i] === ';') i++;
          if (i < code.length && code[i] === '\n') i++;
          continue;
        }
      }
      i++;
    } else {
      result.push(code[i]);
      i++;
    }
  }

  code = result.join('');

  // Remove type annotations
  // Arrow function types: ": () => boolean" etc
  code = code.replace(/:\s*\([^)]*\)\s*=>\s*\w+/g, '');
  // Array types first (before simple types strip the base and leave [])
  code = code.replace(/:\s*(?:string|number|boolean|any)\[\]/g, '');
  code = code.replace(/:\s*RegExp\[\]/g, '');
  code = code.replace(/:\s*(?:AuditEntry|RateLimitState)\[\]/g, '');
  // Record types
  code = code.replace(/:\s*Record<[^>]*>/g, '');
  // Union types: ": string | undefined" etc
  // Note: undefined/null only in union continuations, not standalone — avoids stripping ternary ": undefined"
  code = code.replace(/:\s*(?:string|number|boolean|any|void|never|object|function)(?:\s*\|\s*(?:string|number|boolean|any|void|never|object|undefined|null))*\b/g, '');
  // Custom types
  code = code.replace(/:\s*(?:AuditEntry|RateLimitState|GovernanceRequest|Policy)\b/g, '');
  code = code.replace(/:\s*(?:GovernanceRequest|AuditEntry|RateLimitState|Policy)\["[^"]*"\]/g, '');
  // Function return type annotations: "): { ... } {" → ") {"  (multiline)
  code = code.replace(/\):\s*\{[^}]*\}\s*\{/gs, ') {');
  // Simple function return type annotations: "): string {" etc
  code = code.replace(/\):\s*(?:string|number|boolean|any|void|never)\s*\{/g, ') {');

  // Remove 'as' type assertions
  code = code.replace(/\s+as\s+(?:string|number|any)/g, '');
  code = code.replace(/\s+as\s+(?:GovernanceRequest|AuditEntry)\["[^"]*"\]/g, '');

  // Remove TypeScript non-null assertions: "foo!." → "foo."
  code = code.replace(/(\w)!\./g, '$1.');
  // Remove readonly
  code = code.replace(/readonly\s+/g, '');

  // Convert to CommonJS exports if using export
  if (code.includes('export ')) {
    code = code.replace(/export\s+(?:default\s+)?/g, 'module.exports = ');
  }

  return shebang + code;
}

const tsFile = process.argv[2];
const outFile = process.argv[3];

let code = fs.readFileSync(tsFile, 'utf-8');
const jsCode = transpileTypeScript(code);

fs.writeFileSync(outFile, jsCode, 'utf-8');
console.log(`Transpiled ${tsFile} -> ${outFile}`);
