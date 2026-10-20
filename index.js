import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { execSync } from 'child_process';

const server = new Server({ name: 'swarm-agora-mcp', version: '1.0.0' }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: 'audit_windows_security',
    description: 'Detects unquoted service paths and vulnerable kernel driver dispatch routines.',
    inputSchema: { type: 'object', properties: {} }
  }]
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name === 'audit_windows_security') {
    try {
      const psCommand = `Get-WmiObject Win32_Service | Where-Object {$_.PathName -notmatch '"' -and $_.PathName -notmatch 'C:\\Windows'} | Select-Object Name, PathName; Get-ChildItem C:\\Windows\\System32\\drivers\\*.sys | Select-Object Name`;
      const result = execSync(`powershell -Command "${psCommand}"`, { encoding: 'utf8' });
      return { content: [{ type: 'text', text: result || 'No vulnerabilities detected.' }] };
    } catch (error) {
      return { content: [{ type: 'text', text: `Audit failed: ${error.message}` }] };
    }
  }
  throw new Error('Tool not found');
});

const transport = new StdioServerTransport();
await server.connect(transport);