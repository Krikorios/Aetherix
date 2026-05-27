const fs = require('fs');

const data = JSON.parse(fs.readFileSync('apps/console/eslint_output.json', 'utf8'));

data.forEach(result => {
  const filePath = result.filePath;
  const messages = result.messages;
  
  if (messages.length === 0) return;
  
  let content = fs.readFileSync(filePath, 'utf8');
  let lines = content.split('\n');
  
  // Sort messages descending by line and column to replace from bottom to top
  const unusedVars = messages.filter(m => m.ruleId === '@typescript-eslint/no-unused-vars');
  
  let changed = false;
  
  for (const m of unusedVars) {
    const match = m.message.match(/'([^']+)'/);
    if (!match) continue;
    const varName = match[1];
    
    // search in the first 50 lines for imports
    for(let i=0; i < Math.min(lines.length, 50); i++) {
        let line = lines[i];
        if (line.includes('import ') && line.includes(varName)) {
           let newLine = line;
           newLine = newLine.replace(new RegExp(`\\s*,?\\s*\\b${varName}\\b\\s*,?\\s*`), (match) => {
               if (match.startsWith(',') && match.endsWith(',')) return ', ';
               if (match.startsWith('{ ') && match.endsWith(' }')) return '{ }';
               return ' ';
           });
           newLine = newLine.replace(/\{\s*\}/, '{}');
           newLine = newLine.replace(/import\s*\{\s*\}\s*from\s*['"][^'"]+['"];?/, '');
           
           if (line !== newLine) {
               lines[i] = newLine;
               changed = true;
               console.log(`Removed ${varName} from ${filePath.split('/').pop()}:${i+1}`);
           }
        }
    }
  }
  
  if (changed) {
     fs.writeFileSync(filePath, lines.join('\n'));
  }
});
