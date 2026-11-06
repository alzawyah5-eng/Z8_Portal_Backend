CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE app_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  firebase_uid text NOT NULL UNIQUE,
  email text,
  email_verified boolean NOT NULL DEFAULT false,
  display_name text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now()
);

-- PhotonPay invalidates the prior OAuth token when issuing a new one. Keep one
-- shared token per environment/App ID so multiple API workers never race it.
CREATE TABLE photonpay_tokens (
  token_key text PRIMARY KEY,
  environment text NOT NULL CHECK (environment IN ('sandbox', 'prod')),
  app_id text NOT NULL,
  access_token_ciphertext bytea NOT NULL,
  access_token_iv bytea NOT NULL,
  access_token_tag bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (environment, app_id)
);

CREATE UNIQUE INDEX app_users_email_lower_unique
  ON app_users (lower(email)) WHERE email IS NOT NULL;

CREATE TYPE ledger_account_kind AS ENUM ('customer', 'settlement', 'fee', 'suspense');
CREATE TYPE ledger_transaction_status AS ENUM ('draft', 'posted');

CREATE TABLE ledger_accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id uuid REFERENCES app_users(id) ON DELETE RESTRICT,
  account_ref text NOT NULL UNIQUE,
  kind ledger_account_kind NOT NULL,
  currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'frozen', 'closed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((kind = 'customer' AND owner_user_id IS NOT NULL) OR
         (kind <> 'customer' AND owner_user_id IS NULL))
);

CREATE INDEX ledger_accounts_owner_idx ON ledger_accounts(owner_user_id) WHERE owner_user_id IS NOT NULL;

CREATE FUNCTION guard_ledger_account_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id
     OR NEW.account_ref IS DISTINCT FROM OLD.account_ref
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.currency IS DISTINCT FROM OLD.currency THEN
    RAISE EXCEPTION 'ledger account identity, owner, and currency are immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER ledger_accounts_identity_immutable
  BEFORE UPDATE ON ledger_accounts FOR EACH ROW EXECUTE FUNCTION guard_ledger_account_identity();

CREATE TABLE ledger_transactions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  idempotency_key text NOT NULL UNIQUE CHECK (length(idempotency_key) BETWEEN 8 AND 128),
  reversal_of_transaction_id uuid UNIQUE REFERENCES ledger_transactions(id) ON DELETE RESTRICT,
  status ledger_transaction_status NOT NULL DEFAULT 'draft',
  currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  transaction_type text NOT NULL,
  reference text,
  created_at timestamptz NOT NULL DEFAULT now(),
  posted_at timestamptz,
  CHECK (reversal_of_transaction_id IS NULL OR reversal_of_transaction_id <> id),
  CHECK ((status = 'posted') = (posted_at IS NOT NULL))
);

CREATE FUNCTION guard_posted_transaction_immutability() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'posted' THEN
    RAISE EXCEPTION 'posted ledger transactions are immutable; create a reversal transaction';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER ledger_transactions_immutable
  BEFORE UPDATE OR DELETE ON ledger_transactions
  FOR EACH ROW EXECUTE FUNCTION guard_posted_transaction_immutability();

CREATE TABLE ledger_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_id uuid NOT NULL REFERENCES ledger_transactions(id) ON DELETE RESTRICT,
  account_id uuid NOT NULL REFERENCES ledger_accounts(id) ON DELETE RESTRICT,
  amount_minor bigint NOT NULL CHECK (amount_minor <> 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ledger_entries_account_created_idx ON ledger_entries(account_id, created_at DESC);
CREATE INDEX ledger_entries_transaction_idx ON ledger_entries(transaction_id);

CREATE FUNCTION guard_ledger_entry_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tx_status ledger_transaction_status;
DECLARE tx_currency char(3);
DECLARE account_currency char(3);
DECLARE account_status text;
BEGIN
  -- Serialize entry creation against posting, so the deferred balance check
  -- cannot race with another transaction adding an entry.
  SELECT status, currency INTO tx_status, tx_currency
    FROM ledger_transactions WHERE id = NEW.transaction_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'ledger transaction does not exist'; END IF;
  IF tx_status <> 'draft' THEN RAISE EXCEPTION 'entries can only be added to draft transactions'; END IF;
  SELECT currency, status INTO account_currency, account_status
    FROM ledger_accounts WHERE id = NEW.account_id FOR UPDATE;
  IF NOT FOUND OR account_currency <> tx_currency THEN
    RAISE EXCEPTION 'ledger entry account currency must match transaction currency';
  END IF;
  IF account_status <> 'active' THEN RAISE EXCEPTION 'ledger account is not active'; END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER ledger_entries_insert_guard
  BEFORE INSERT ON ledger_entries FOR EACH ROW EXECUTE FUNCTION guard_ledger_entry_insert();

CREATE FUNCTION guard_posted_ledger_immutability() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tx_id uuid;
DECLARE tx_status ledger_transaction_status;
BEGIN
  tx_id := COALESCE(OLD.transaction_id, NEW.transaction_id);
  SELECT status INTO tx_status FROM ledger_transactions WHERE id = tx_id;
  IF TG_OP <> 'INSERT' OR tx_status <> 'draft' THEN
    RAISE EXCEPTION 'ledger entries are append-only; post a reversal transaction instead';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER ledger_entries_immutable
  BEFORE UPDATE OR DELETE ON ledger_entries FOR EACH ROW EXECUTE FUNCTION guard_posted_ledger_immutability();

CREATE FUNCTION validate_ledger_posting() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tx_id uuid;
DECLARE tx_status ledger_transaction_status;
DECLARE entry_count bigint;
DECLARE balance numeric;
BEGIN
  tx_id := COALESCE(NEW.id, OLD.id);
  SELECT status INTO tx_status FROM ledger_transactions WHERE id = tx_id;
  IF tx_status = 'posted' THEN
    SELECT count(*), COALESCE(sum(amount_minor), 0)
      INTO entry_count, balance FROM ledger_entries WHERE transaction_id = tx_id;
    IF entry_count < 2 OR balance <> 0 THEN
      RAISE EXCEPTION 'posted ledger transaction must have at least two entries and balance to zero';
    END IF;

    IF (SELECT reversal_of_transaction_id FROM ledger_transactions WHERE id = tx_id) IS NOT NULL THEN
      IF NOT EXISTS (
        SELECT 1 FROM ledger_transactions original
        WHERE original.id = (
          SELECT reversal_of_transaction_id FROM ledger_transactions WHERE id = tx_id
        ) AND original.status = 'posted'
          AND original.currency = (SELECT currency FROM ledger_transactions WHERE id = tx_id)
      ) THEN
        RAISE EXCEPTION 'a reversal must refer to an already posted transaction';
      END IF;
      IF EXISTS (
        SELECT 1
        FROM (
          SELECT account_id, sum(amount_minor) AS amount
          FROM ledger_entries WHERE transaction_id = tx_id GROUP BY account_id
        ) reversal
        FULL JOIN (
          SELECT account_id, sum(amount_minor) AS amount
          FROM ledger_entries
          WHERE transaction_id = (
            SELECT reversal_of_transaction_id FROM ledger_transactions WHERE id = tx_id
          ) GROUP BY account_id
        ) original USING (account_id)
        WHERE COALESCE(reversal.amount, 0) <> -COALESCE(original.amount, 0)
      ) THEN
        RAISE EXCEPTION 'reversal entries must exactly offset the original entries by account';
      END IF;
    END IF;
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER ledger_transaction_balance_check
  AFTER INSERT OR UPDATE OF status ON ledger_transactions DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION validate_ledger_posting();
