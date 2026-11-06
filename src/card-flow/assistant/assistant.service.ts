import { BadRequestException, ForbiddenException, Inject, Injectable, Logger, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { FirebasePrincipal } from '../../auth/firebase-principal';
import { CardFlowEntitiesService } from '../card-flow-entities.service';
import { LocalWorkflowContextFactory } from '../workflow-context.factory';
import photonpayCards from '../legacy/photonpay-cards';
import photonpayDiagnostics from '../legacy/photonpay-diagnostics';
import photonpaySync from '../legacy/photonpay-sync';
import sendProgrammeAlert from '../legacy/send-programme-alert';

const ALLOWED_AGENTS = new Set(['cardholder_assistant', 'card_setup_assistant', 'technical_support']);
const PRIVATE_KEYS = /^(?:pan|panno|card_number|cardnumber|card_no|cardno|cvv|cvv2|cvc|security_code|securitycode|access_token|accesstoken|refresh_token|refreshtoken|id_token|idtoken|customtoken|firebasecustomtoken|firebase_uid|firebaseuid|token|private_key|privatekey|password|secret|authorization|signed_url|signedurl|cert_id|certid|date_of_birth|dateofbirth|front_file_uri|frontfileuri|back_file_uri|backfileuri|proof_file_uri|prooffileuri|email|phone|mobile|full_name|fullname|first_name|firstname|last_name|lastname|address|address_line|addressline|postal_code|postalcode|nationality|country|city|state|review_reason|reviewnote|notes|device_ip|device_country)$/i;
const USER_CARD_FIELDS = ['id','nickname','last4','expiry','currency','scheme','card_type','form_factor','status','balance','monthly_spend','max_on_daily','max_on_monthly','max_on_percent','transaction_limit_type'];
const USER_TX_FIELDS = ['id','kind','event','card_id','card_last4','merchant','amount','currency','status','category','occurred_at'];
const HOLDER_FIELDS = ['id','status','photon_cardholder_id','provider_status','review_status'];

@Injectable()
export class AssistantService {
  private readonly logger = new Logger(AssistantService.name);

  constructor(
    @Inject('PG_POOL') private readonly db: Pool,
    private readonly config: ConfigService,
    private readonly entities: CardFlowEntitiesService,
    private readonly contextFactory: LocalWorkflowContextFactory,
  ) {}

  async list(principal: FirebasePrincipal, agentName?: string) {
    const owner = await this.ownerId(principal);
    if (agentName && !ALLOWED_AGENTS.has(agentName)) throw new BadRequestException({ code: 'invalid_agent' });
    const result = await this.db.query(
      `SELECT id, agent_name, metadata, messages, created_at, updated_at FROM assistant_conversations
       WHERE owner_user_id = $1 ${agentName ? 'AND agent_name = $2' : ''} ORDER BY updated_at DESC LIMIT 30`,
      agentName ? [owner, agentName] : [owner],
    );
    return { items: result.rows.map((row) => this.format(row)), has_more: false, next_cursor: null };
  }

  async create(principal: FirebasePrincipal, input: { agent_name: string; metadata?: Record<string, unknown> }) {
    this.assertAgentAccess(principal, input.agent_name);
    const owner = await this.ownerId(principal);
    const id = randomUUID();
    const metadata = this.safeMetadata(input.metadata ?? {});
    const result = await this.db.query(
      `INSERT INTO assistant_conversations (id, owner_user_id, agent_name, metadata)
       VALUES ($1, $2, $3, $4) RETURNING id, agent_name, metadata, messages, created_at, updated_at`,
      [id, owner, input.agent_name, JSON.stringify(metadata)],
    );
    return this.format(result.rows[0]);
  }

  async get(principal: FirebasePrincipal, id: string) {
    const row = await this.getOwned(principal, id);
    return this.format(row);
  }

  async addMessage(principal: FirebasePrincipal, id: string, contentInput: string) {
    const content = String(contentInput ?? '').trim();
    if (!content || content.length > 4000) throw new BadRequestException({ code: 'invalid_message' });
    const row = await this.getOwned(principal, id);
    const config = await this.agent(row.agent_name);
    const messages = Array.isArray(row.messages) ? row.messages : [];
    const history = this.responsesHistory(row.model_history, messages);
    const userMessage = { role: 'user', content, created_date: new Date().toISOString(), metadata: { created_date: new Date().toISOString() } };
    messages.push(userMessage);
    history.push({ role: 'user', content });
    const toolCalls = [];
    let finalText = '';
    for (let iteration = 0; iteration < 5; iteration += 1) {
      const response = await this.generate(config, history);
      const output = Array.isArray(response?.output) ? response.output : [];
      if (!output.length) throw new ServiceUnavailableException({ code: 'assistant_unavailable', message: 'The assistant did not return a response.' });
      history.push(...output);
      const calls = output.filter((item: any) => item.type === 'function_call' && item.name);
      finalText = this.responseText(response).trim();
      if (!calls.length) break;
      for (const call of calls) {
        const callId = String(call.call_id || call.id || randomUUID());
        const args = this.parseObject(call.arguments);
        const toolCall: any = { id: callId, name: call.name, arguments_string: JSON.stringify(args), status: 'running' };
        toolCalls.push(toolCall);
        let result;
        try {
          result = await this.executeTool(config, call.name, args, principal, messages);
          result = this.safeForModel(result, call.name);
          toolCall.status = 'completed';
        } catch (error) {
          result = { error: error instanceof Error ? error.message.slice(0, 300) : 'The requested operation was refused.' };
          toolCall.status = 'failed';
        }
        toolCall.results = JSON.stringify(result);
        history.push({ type: 'function_call_output', call_id: callId, output: JSON.stringify(result) });
      }
    }
    if (!finalText && !toolCalls.length) finalText = 'I could not complete that. Please try again or contact Z8 support.';
    messages.push({ role: 'assistant', content: finalText, tool_calls: toolCalls, created_date: new Date().toISOString(), metadata: { created_date: new Date().toISOString() } });
    if (messages.length > 100) messages.splice(0, messages.length - 100);
    if (history.length > 120) history.splice(0, history.length - 120);
    await this.db.query(
      `UPDATE assistant_conversations SET messages = $2, model_history = $3, updated_at = now()
       WHERE id = $1`, [id, JSON.stringify(messages), JSON.stringify(history)],
    );
    return this.get(principal, id);
  }

  private async generate(agent: any, history: any[]) {
    const apiKey = this.config.get<string>('GPT_AI_API_KEY', '').trim();
    if (!apiKey) throw new ServiceUnavailableException({ code: 'assistant_not_configured', message: 'The assistant is not configured yet.' });
    const model = this.config.get<string>('GPT_AI_MODEL', 'gpt-6-astra').trim();
    const declarations = this.toolDeclarations(agent);
    let response: Response;
    try {
      response = await fetch('https://api.openai.com/v1/responses', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({
          model,
          instructions: `${agent.instructions}\n\nSecurity rules: Use tools only for the signed-in user's permitted records. Never request or reveal full card numbers, CVVs, credentials, identity-document numbers or private file links. Before any action that changes a card, account, record or provider state, explain it and wait for the user to explicitly confirm in their next message. Never claim an action succeeded unless a tool result confirms it.`,
          input: history,
          ...(declarations.length ? { tools: declarations } : {}),
          max_output_tokens: 1024,
          reasoning: { effort: this.config.get<string>('GPT_AI_REASONING_EFFORT', 'medium') },
        }),
        signal: AbortSignal.timeout(30000),
      });
    } catch (error) {
      const reason = error instanceof Error ? error.name : 'network_error';
      this.logger.warn(`GPT Responses API request failed before a response; reason=${reason}`);
      throw new ServiceUnavailableException({ code: 'assistant_unavailable', message: 'The assistant service is temporarily unavailable.' });
    }
    if (!response.ok) {
      const payload: any = await response.json().catch(() => null);
      const providerError = payload?.error ?? {};
      const safePart = (value: unknown) => String(value ?? '').replace(/[^a-zA-Z0-9_.:-]/g, '').slice(0, 80) || 'none';
      const requestId = safePart(response.headers.get('x-request-id'));
      this.logger.error(`GPT Responses API rejected request; status=${response.status}; type=${safePart(providerError.type)}; code=${safePart(providerError.code)}; request_id=${requestId}`);
      throw new ServiceUnavailableException({ code: 'assistant_unavailable', message: 'The assistant service is temporarily unavailable.' });
    }
    return response.json();
  }

  private responseText(response: any): string {
    if (typeof response?.output_text === 'string') return response.output_text;
    return (response?.output ?? [])
      .filter((item: any) => item.type === 'message')
      .flatMap((item: any) => item.content ?? [])
      .filter((part: any) => part.type === 'output_text' && typeof part.text === 'string')
      .map((part: any) => part.text)
      .join('\n');
  }

  private responsesHistory(history: any, messages: any[]): any[] {
    if (Array.isArray(history) && !history.some((item) => item?.parts || item?.content?.parts)) return history;
    // Existing conversations used the previous model's private history shape.
    // Rebuild a plain transcript so those conversations survive the provider switch.
    return messages
      .filter((item) => ['user', 'assistant'].includes(item?.role) && typeof item.content === 'string' && item.content.trim())
      .slice(-60)
      .map((item) => ({ role: item.role, content: item.content.slice(0, 4000) }));
  }

  private toolDeclarations(agent: any) {
    const declarations = [];
    for (const tool of agent.tool_configs ?? []) {
      if (tool.entity_name && Array.isArray(tool.allowed_operations)) {
        const operations = new Set(tool.allowed_operations);
        for (const operation of ['read', 'create', 'update', 'delete']) {
          if (!operations.has(operation)) continue;
          const properties: any = { record_id: { type: 'string' } };
          if (operation === 'read') properties.filter_json = { type: 'string', description: 'Optional JSON object of exact filters.' };
          if (operation === 'create' || operation === 'update') properties.data_json = { type: 'string', description: 'JSON object containing record fields.' };
          declarations.push({
            type: 'function', name: `${operation}_${tool.entity_name}`,
            description: `${operation} permitted ${tool.entity_name} records.`,
            parameters: { type: 'object', properties },
          });
        }
      }
      if (tool.function_name === 'photonpayCards') declarations.push({ type: 'function', name: 'photonpayCards', description: tool.description ?? 'Use the authorized Z8 card service.', parameters: { type: 'object', properties: { action: { type: 'string' }, payload_json: { type: 'string', description: 'JSON object with the action payload.' } }, required: ['action'] } });
      if (tool.function_name === 'photonpayDiagnostics') declarations.push({ type: 'function', name: 'photonpayDiagnostics', description: tool.description ?? 'Run a PhotonPay configuration check.', parameters: { type: 'object', properties: { options_json: { type: 'string' } } } });
    }
    return declarations;
  }

  private async executeTool(agent: any, name: string, args: any, principal: FirebasePrincipal, previousMessages: any[]) {
    const entityMatch = name.match(/^(read|create|update|delete)_(AccountEntry|Card|Cardholder|CardholderApplication|CardRequest|CardTransaction|Notification|ProgrammeSettings|User)$/);
    if (entityMatch) {
      const [, operation, entity] = entityMatch;
      const permission = (agent.tool_configs ?? []).find((item: any) => item.entity_name === entity)?.allowed_operations ?? [];
      if (!permission.includes(operation)) throw new ForbiddenException('This assistant cannot perform that operation.');
      if (operation !== 'read') this.requireConfirmation(previousMessages);
      if (operation === 'read') {
        if (args.record_id) return this.entities.get(entity, String(args.record_id), principal);
        const filter = this.parseObject(args.filter_json);
        return this.entities.filter(entity, filter, { limit: 30 }, principal);
      }
      if (operation === 'create') return this.entities.create(entity, this.parseObject(args.data_json), principal);
      if (operation === 'update') return this.entities.update(entity, String(args.record_id ?? ''), this.parseObject(args.data_json), principal);
      return this.entities.remove(entity, String(args.record_id ?? ''), principal);
    }
    const fnConfig = (agent.tool_configs ?? []).find((item: any) => item.function_name === name);
    if (!fnConfig) throw new ForbiddenException('This assistant cannot call that operation.');
    if (name === 'photonpayCards') {
      const action = String(args.action ?? '');
      if (!/^(status|bins|balance|list|detail|refresh|my_registration|my_wallet|my_deposit_proof|wallet_overview|wallet_client|application_photo)$/.test(action)) this.requireConfirmation(previousMessages);
      const payload = this.parseObject(args.payload_json);
      return this.callFunction(photonpayCards, principal, { action, payload });
    }
    if (name === 'photonpayDiagnostics') return this.callFunction(photonpayDiagnostics, principal, this.parseObject(args.options_json));
    throw new ForbiddenException('This assistant cannot call that operation.');
  }

  private async callFunction(handler: Function, principal: FirebasePrincipal, body: any) {
    const req = new Request('https://z8.local/v1/functions/assistant', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const response = await (handler as any)(req, this.contextFactory.create(principal));
    const text = await response.text();
    let result: any;
    try { result = JSON.parse(text); } catch { result = { message: text.slice(0, 500) }; }
    if (!response.ok) throw new BadRequestException(result);
    return result;
  }

  private requireConfirmation(messages: any[]) {
    const previousAssistant = [...messages].reverse().find((item) => item.role === 'assistant')?.content ?? '';
    const latestUser = [...messages].reverse().find((item) => item.role === 'user')?.content ?? '';
    if (!/\b(confirm|shall i|would you like me to|should i|before i proceed|please say yes)\b/i.test(previousAssistant)
      || !/^(yes|confirm|confirmed|do it|proceed|go ahead|please do)[.!\s]*$/i.test(String(latestUser).trim())) {
      throw new ForbiddenException('Ask for the user’s explicit confirmation before making changes.');
    }
  }

  private parseObject(value: unknown) {
    if (!value) return {};
    if (typeof value === 'object' && !Array.isArray(value)) return value;
    try {
      const parsed = JSON.parse(String(value));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch { /* safe validation error below */ }
    throw new BadRequestException({ code: 'invalid_tool_arguments' });
  }

  private safeForModel(value: any, toolName: string): any {
    const entity = toolName.match(/^(?:read|create|update|delete)_(\w+)$/)?.[1];
    const rows = value?.items ?? value;
    if (entity && Array.isArray(rows)) {
      const fields = entity === 'Card' ? USER_CARD_FIELDS : entity === 'CardTransaction' ? USER_TX_FIELDS : entity === 'Cardholder' ? HOLDER_FIELDS : null;
      if (fields) return this.scrub(Array.isArray(value)
        ? rows.map((row) => this.pickFields(row, fields))
        : { ...value, items: rows.map((row) => this.pickFields(row, fields)) });
    }
    return this.scrub(value);
  }

  private pickFields(row: any, fields: string[]) { return Object.fromEntries(fields.filter((key) => row?.[key] !== undefined).map((key) => [key, row[key]])); }
  private scrub(value: any): any {
    if (Array.isArray(value)) return value.slice(0, 50).map((item) => this.scrub(item));
    if (!value || typeof value !== 'object') return typeof value === 'string'
      ? value.replace(/(?:\d[ -]?){13,19}/g, '[redacted card number]').slice(0, 2000)
      : value;
    return Object.fromEntries(Object.entries(value).filter(([key]) => !PRIVATE_KEYS.test(key.replace(/[_-]/g, ''))).map(([key, item]) => [key, this.scrub(item)]));
  }

  private async agent(name: string) {
    if (!ALLOWED_AGENTS.has(name)) throw new BadRequestException({ code: 'invalid_agent' });
    const path = join(__dirname, 'agents', `${name}.jsonc`);
    try { return JSON.parse(await readFile(path, 'utf8')); }
    catch { throw new ServiceUnavailableException({ code: 'assistant_not_configured' }); }
  }

  private assertAgentAccess(principal: FirebasePrincipal, name: string) {
    if (!ALLOWED_AGENTS.has(name)) throw new BadRequestException({ code: 'invalid_agent' });
    const isAdminAgent = name !== 'cardholder_assistant';
    if (isAdminAgent !== (principal.role === 'admin')) throw new ForbiddenException('This assistant is not available to this account.');
  }

  private async ownerId(principal: FirebasePrincipal) {
    const result = await this.db.query('SELECT id FROM app_users WHERE firebase_uid = $1 AND deleted_at IS NULL', [principal.uid]);
    if (!result.rowCount) throw new NotFoundException({ code: 'user_not_registered' });
    return result.rows[0].id;
  }

  private async getOwned(principal: FirebasePrincipal, id: string) {
    if (!/^[0-9a-f-]{36}$/i.test(id)) throw new BadRequestException({ code: 'invalid_conversation_id' });
    const owner = await this.ownerId(principal);
    const result = await this.db.query('SELECT * FROM assistant_conversations WHERE id = $1 AND owner_user_id = $2', [id, owner]);
    if (!result.rowCount) throw new NotFoundException({ code: 'conversation_not_found' });
    this.assertAgentAccess(principal, result.rows[0].agent_name);
    return result.rows[0];
  }

  private safeMetadata(value: Record<string, unknown>) {
    return { name: String(value.name ?? '').slice(0, 80), description: String(value.description ?? '').slice(0, 240) };
  }

  private format(row: any) {
    return { id: row.id, agent_name: row.agent_name, metadata: row.metadata ?? {}, messages: row.messages ?? [], created_date: new Date(row.created_at).toISOString(), updated_date: new Date(row.updated_at).toISOString() };
  }
}
