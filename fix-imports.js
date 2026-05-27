const fs = require('fs');

const data = JSON.parse(fs.readFileSync('eslint_output.json', 'utf8'));

data.forEach(result => {
  const filePath = result.filePath;
  const messages = result.messages;
  
  if (messages.length === 0) return;
  
  let content = fs.readFileSync(filePath, 'utf8');
  let lines = content.split('\n');
  
  // Sort messages descending by line and column to replace from bottom to top
  const unusedVars = messages.filter(m => m.ruleId === '@typescript-eslint/no-unused-vars');
  
  // A naive approach: if it's an import line, and it says "X is defined but never used", we can replace "X, " or ", X" or "{ X }" in that line.
  // Actually we can just run a regex on the file content for the specific variable name if it's an import.
  
  let changed = false;
  
  for (const m of unusedVars) {
    const match = m.message.match(/'([^']+)' is defined but never used/);
    if (!match) continue;
    const varName = match[1];
    const lineIndex = m.line - 1;
    let line = lines[lineIndex];
    
    // For import statements, remove the variable name.
    if (line.includes('import ') && line.includes(varName)) {
       // match exactly the varName, considering it could be '{ VarName }', '{ VarName, ', ', VarName', 'VarName,'
       // We'll use a regex that handles word boundaries and optional commas.
       
       let newLine = line;
       newLine = newLine.replace(new RegExp(`\\s*,?\\s*\\b${varName}\\b\\s*,?\\s*`), (match) => {
           if (match.startsWith(',') && match.endsWith(',')) return ', ';
           if (match.startsWith('{ ') && match.endsWith(' }')) return '{ }';
           return ' ';
       });
       // clean up { } or empty imports
       newLine = newLine.replace(/\{\s*\}/, '{}');
       newLine = newLine.replace(/import\s*\{\s*\}\s*from\s*['"][^'"]+['"];?/, '');
       
       if (line !== newLine) {
           lines[lineIndex] = newLine;
           changed = true;
       }
    }
  }
  
  if (changed) {
     fs.writeFileSync(filePath, lines.join('\n'));
     console.log('Fixed imports in', filePath);
  }
});
