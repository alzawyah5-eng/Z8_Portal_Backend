import { DecodedIdToken } from 'firebase-admin/auth';

export type FirebasePrincipal = Pick<DecodedIdToken, 'uid' | 'email' | 'email_verified' | 'name' | 'admin'> & {
  sign_in_provider?: string;
  role?: 'admin' | 'user' | null;
};
