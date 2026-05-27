const fs = require('fs');

const data = JSON.parse(fs.readFileSync('apps/console/eslint_output.json', 'utf8'));

data.forEach(result => {
  const filePath = result.filePath;
  const messages = result.messages;
  
  if (messages.length === 0) return;
  
  let content = fs.readFileSync(filePath, 'utf8');
  let changed = false;
  
  const unusedVars = messages.filter(m => m.ruleId === '@typescript-eslint/no-unused-vars');
  
  for (const m of unusedVars) {
    const match = m.message.match(/'([^']+)'/);
    if (!match) continue;
    const varName = match[1];
    
    // check if it's imported from lucide-react
    if (content.includes('lucide-react') && content.includes(varName)) {
        // remove the var name from the file
        // be careful not to remove it from elsewhere. We can just replace \bvarName\b, or \bvarName\n in the import block.
        // Let's do a simple regex to replace the variable name in the import section (top 2000 chars)
        let importSection = content.substring(0, 2000);
        let remainder = content.substring(2000);
        
        let newImportSection = importSection.replace(new RegExp(`\\b${varName}\\b\\s*,?\\s*`), '');
        
        if (importSection !== newImportSection) {
            content = newImportSection + remainder;
            changed = true;
            console.log(`Removed ${varName} from ${filePath.split('/').pop()}`);
        }
    }
  }
  
  if (changed) {
     fs.writeFileSync(filePath, content);
  }
});
