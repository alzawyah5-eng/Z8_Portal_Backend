import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import { CardFlowEntitiesService } from './card-flow-entities.service';
import { PrivateFileStorageService } from '../files/private-file-storage.service';
import { FirebasePrincipal } from '../auth/firebase-principal';
import { Auth } from 'firebase-admin/auth';

@Injectable()
export class LocalWorkflowContextFactory {
  constructor(
    private readonly records: CardFlowEntitiesService,
    private readonly files: PrivateFileStorageService,
    private readonly config: ConfigService,
    @Inject('PG_POOL') private readonly db: Pool,
    @Inject('FIREBASE_AUTH') private readonly auth: Auth,
  ) {}

  create(principal?: FirebasePrincipal) {
    const entities: Record<string, any> = {};
    const names = ['AccountEntry', 'Card', 'Cardholder', 'CardholderApplication', 'CardRequest', 'CardTransaction', 'Notification', 'PhotonPayLog', 'PhotonPayToken', 'ProgrammeSettings', 'User'];
    for (const entity of names) {
      entities[entity] = {
        filter: async (filter: any = {}, options: any = {}) => {
          if (entity === 'PhotonPayToken') {
            const token = await this.records.getPhotonPayToken(String(filter.key ?? ''));
            return token ? [token] : [];
          }
          return this.records.filter(entity, filter, options, principal, true);
        },
        list: (options = {}) => this.records.list(entity, options, principal, true),
        get: (id: string) => this.records.get(entity, id, principal, true),
        create: (data: any) => entity === 'PhotonPayToken'
          ? this.records.savePhotonPayToken(data)
          : this.records.create(entity, data, principal, true),
        update: (id: string, data: any) => entity === 'PhotonPayToken'
          ? this.records.savePhotonPayToken(data)
          : this.records.update(entity, id, data, principal, true),
        delete: (id: string) => this.records.remove(entity, id, principal, true),
        updateMany: (filter: any, update: any) => this.records.updateMany(entity, filter, update, principal, true),
      };
    }
    const email = principal?.email ?? '';
    const profile = principal ? {
      id: principal.uid,
      email,
      full_name: principal.name ?? '',
      display_name: principal.name ?? '',
      role: principal.role ?? 'user',
    } : null;
    return {
      auth: {
        me: async () => {
          if (!profile) throw Object.assign(new Error('Unauthorized'), { status: 401 });
          return profile;
        },
      },
      entities,
      accounts: {
        close: async (firebaseUid: string) => {
          const result = await this.records.closeUserAccount(firebaseUid);
          try {
            await this.auth.deleteUser(result.firebaseUid);
          } catch {
            // The PostgreSQL tombstone blocks app access. Disable the Firebase
            // identity as a fallback if permanent provider cleanup is unavailable.
            try {
              await this.auth.updateUser(result.firebaseUid, { disabled: true });
              await this.auth.revokeRefreshTokens(result.firebaseUid);
            } catch {
              // Keep the database tombstone authoritative while Firebase recovers.
            }
          }
          return result;
        },
      },
      files: {
        uploadPrivateFile: ({ file }: { file: File }) => this.files.uploadPrivateFile(file),
        readPrivateFile: (file_uri: string) => this.files.readPrivateFile(file_uri),
        deletePrivateFile: (file_uri: string) => this.files.deletePrivateFile(file_uri),
        createSignedUrl: ({ file_uri, expires_in }: { file_uri: string; expires_in: number }) =>
          this.files.createSignedUrl(file_uri, expires_in),
      },
      mailer: { send: (message: any) => this.sendEmail(message) },
    };
  }

  private async sendEmail(message: any) {
    const host = this.config.get<string>('SMTP_HOST', '').trim();
    const user = this.config.get<string>('SMTP_USER', '').trim();
    const pass = this.config.get<string>('SMTP_PASSWORD', '');
    if (!host || !user || !pass) throw new Error('SMTP is not configured.');
    const port = Number(this.config.get('SMTP_PORT', 587));
    const transport = nodemailer.createTransport({
      host, port,
      secure: this.config.get('SMTP_SECURE', 'false') === 'true' || port === 465,
      auth: { user, pass },
    });
    const variables = message.variables ?? {};
    const template = String(message.template_name ?? 'Z8 alert');
    const summary = Object.entries(variables).map(([key, value]) => `${key.replace(/_/g, ' ')}: ${String(value)}`).join('\n');
    return transport.sendMail({
      from: this.config.get<string>('SMTP_FROM', user), to: message.to,
      subject: `Z8 Portal: ${template.replace(/([A-Z])/g, ' $1').trim()}`,
      text: `A Z8 Portal alert was generated.\n\n${summary}`,
    });
  }
}
