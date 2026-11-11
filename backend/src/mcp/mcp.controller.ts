import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { JsonRpcRequest, McpServerService } from './mcp-server.service';
import { Public } from '../common/decorators/public.decorator';

@Controller('mcp')
export class McpController {
  constructor(private readonly mcpServerService: McpServerService) {}

  /**
   * Catálogo de herramientas disponibles en el servidor MCP.
   */
  @Get('tools')
  @Public()
  getTools() {
    return {
      tools: this.mcpServerService.getToolsCatalog(),
    };
  }

  /**
   * Endpoint estándar JSON-RPC 2.0 para clientes MCP (Cursor, Claude Desktop, LangChain).
   */
  @Post('rpc')
  @Public()
  @HttpCode(HttpStatus.OK)
  async handleRpc(
    @Body() body: JsonRpcRequest,
    @Headers('x-api-key') headerApiKey?: string,
    @Headers('authorization') authHeader?: string,
    @Query('apiKey') queryApiKey?: string,
  ) {
    const rawKey = this.extractApiKey(headerApiKey, authHeader, queryApiKey);
    if (!rawKey) {
      throw new UnauthorizedException('Se requiere una clave de API válida (X-API-Key o Bearer token)');
    }

    const { organizationId } = await this.mcpServerService.authenticateApiKey(rawKey);
    return this.mcpServerService.handleJsonRpc(body, organizationId);
  }

  /**
   * Endpoint de Server-Sent Events (SSE) para transporte MCP sobre HTTP.
   */
  @Get('sse')
  @Public()
  async handleSse(
    @Req() req: Request,
    @Res() res: Response,
    @Headers('x-api-key') headerApiKey?: string,
    @Headers('authorization') authHeader?: string,
    @Query('apiKey') queryApiKey?: string,
  ) {
    const rawKey = this.extractApiKey(headerApiKey, authHeader, queryApiKey);
    if (!rawKey) {
      res.status(HttpStatus.UNAUTHORIZED).json({ error: 'Se requiere una clave de API válida' });
      return;
    }

    try {
      await this.mcpServerService.authenticateApiKey(rawKey);

      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders();

      const sessionId = `mcp_sess_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
      const messageEndpoint = `/api/v1/mcp/messages?sessionId=${sessionId}&apiKey=${encodeURIComponent(rawKey)}`;

      // Evento inicial según especificación MCP SSE transport
      res.write(`event: endpoint\ndata: ${messageEndpoint}\n\n`);

      // Mantener vivo el canal SSE
      const keepAlive = setInterval(() => {
        res.write(': ping\n\n');
      }, 15000);

      req.on('close', () => {
        clearInterval(keepAlive);
        res.end();
      });
    } catch {
      res.status(HttpStatus.UNAUTHORIZED).json({ error: 'Clave de API inválida' });
    }
  }

  /**
   * Endpoint para recibir mensajes enviados por el cliente conectado vía SSE.
   */
  @Post('messages')
  @Public()
  @HttpCode(HttpStatus.OK)
  async handleMessages(
    @Body() body: JsonRpcRequest,
    @Headers('x-api-key') headerApiKey?: string,
    @Headers('authorization') authHeader?: string,
    @Query('apiKey') queryApiKey?: string,
  ) {
    const rawKey = this.extractApiKey(headerApiKey, authHeader, queryApiKey);
    if (!rawKey) {
      throw new UnauthorizedException('Se requiere una clave de API válida');
    }

    const { organizationId } = await this.mcpServerService.authenticateApiKey(rawKey);
    return this.mcpServerService.handleJsonRpc(body, organizationId);
  }

  private extractApiKey(headerApiKey?: string, authHeader?: string, queryApiKey?: string): string | null {
    if (headerApiKey && headerApiKey.trim()) {
      return headerApiKey.trim();
    }
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.replace('Bearer ', '').trim();
    }
    if (queryApiKey && queryApiKey.trim()) {
      return queryApiKey.trim();
    }
    return null;
  }
}
