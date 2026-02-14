const fs = require('fs');

let code = fs.readFileSync('scripts/governance-gateway.js', 'utf-8');

// Remove all interface blocks
// This is a multi-line block remover
code = code.replace(/^interface\s+\w+[^{]*\{(?:[^{}]|(?:\{[^{}]*\}))*\}\s*\n/gm, '');

// Remove any remaining "interface" lines
code = code.replace(/^interface\s+[^\n]*\n/gm, '');
code = code.replace(/^  [^}][^\n]*\n/gm, (match) => {
  // Keep normal indented code, not interface body parts
  if (match.includes('readonly') || match.includes('const ') || match.includes('function')) {
    return match;
  }
  if (match.match(/^\s+[a-zA-Z_]\w+\s*[?]?;/)) {
    // This looks like an interface property, skip it  
    return '';
  }
  return match;
});

// Clean up the interface blocks that remain by removing their contents
code = code.replace(/interface[^{]*\{[^}]*\}\n*/g, '');

fs.writeFileSync('scripts/governance-gateway.js', code, 'utf-8');
console.log('Fixed transpiled file');
