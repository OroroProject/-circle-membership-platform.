-- CIRCLE V21.1 · SIMULATED ELIGIBILITY & ONE-TIME PARTNER VERIFICATION
-- Run ONLY in the EXISTING MAIN CIRCLE Supabase project, AFTER confirming a backup.
-- Requires successful circle-v21-setup.sql. Adds separate demo-only data; no real payments,
-- employment verification, redeemable offers or live partner privileges.
-- SECURITY: issuer is Founder-only; partner verifier is explicitly assigned; callers
-- cannot insert/update entitlement, verifier or pass rows directly.
BEGIN;

CREATE TABLE IF NOT EXISTS public.circle_v211_entitlements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  source_type text NOT NULL CHECK (source_type IN ('corporate','individual')),
  source_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'active_demo' CHECK (state IN ('active_demo','revoked_demo')),
  starts_at timestamptz NOT NULL DEFAULT now(),
  ends_at timestamptz NOT NULL,
  created_by uuid NOT NULL REFERENCES auth.users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  CHECK (ends_at > starts_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS circle_v211_one_active_source
 ON public.circle_v211_entitlements(user_id,source_type,source_id) WHERE state='active_demo';
CREATE INDEX IF NOT EXISTS circle_v211_ent_by_user ON public.circle_v211_entitlements(user_id,state,ends_at);

CREATE TABLE IF NOT EXISTS public.circle_v211_partner_verifiers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  partner_id uuid NOT NULL REFERENCES public.circle_v21_partners(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_by uuid NOT NULL REFERENCES auth.users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(partner_id,user_id)
);
CREATE INDEX IF NOT EXISTS circle_v211_verifiers_user ON public.circle_v211_partner_verifiers(user_id);

CREATE TABLE IF NOT EXISTS public.circle_v211_demo_passes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  partner_id uuid NOT NULL REFERENCES public.circle_v21_partners(id) ON DELETE RESTRICT,
  offer_id uuid NOT NULL REFERENCES public.circle_v21_offers(id) ON DELETE RESTRICT,
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  verified_at timestamptz,
  verified_by uuid REFERENCES auth.users(id),
  CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS circle_v211_pass_by_user ON public.circle_v211_demo_passes(user_id,created_at DESC);

ALTER TABLE public.circle_v211_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.circle_v211_partner_verifiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.circle_v211_demo_passes ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.circle_v211_entitlements, public.circle_v211_partner_verifiers,
 public.circle_v211_demo_passes FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.circle_v211_entitlements,
 public.circle_v211_partner_verifiers,public.circle_v211_demo_passes TO authenticated;

DROP POLICY IF EXISTS v211_read_entitlements ON public.circle_v211_entitlements;
CREATE POLICY v211_read_entitlements ON public.circle_v211_entitlements FOR SELECT TO authenticated
 USING (user_id=(SELECT auth.uid()) OR public.circle_v21_is_founder());
DROP POLICY IF EXISTS v211_read_verifiers ON public.circle_v211_partner_verifiers;
CREATE POLICY v211_read_verifiers ON public.circle_v211_partner_verifiers FOR SELECT TO authenticated
 USING (user_id=(SELECT auth.uid()) OR public.circle_v21_is_founder());
DROP POLICY IF EXISTS v211_read_passes ON public.circle_v211_demo_passes;
CREATE POLICY v211_read_passes ON public.circle_v211_demo_passes FOR SELECT TO authenticated
 USING (user_id=(SELECT auth.uid()) OR public.circle_v21_is_founder());

-- Private helper: offer must be visible and the caller has a live Founder-issued DEMO entitlement
-- sourced from their own existing V21 roster link or lifestyle-plan interest.
CREATE OR REPLACE FUNCTION public.circle_v211_eligibility_internal(p_user uuid,p_offer uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path='' AS $$
DECLARE o public.circle_v21_offers%ROWTYPE;
        e public.circle_v211_entitlements%ROWTYPE;
BEGIN
  IF p_user IS NULL THEN RETURN jsonb_build_object('eligible_demo',false,'reason','Sign in required'); END IF;
  SELECT * INTO o FROM public.circle_v21_offers WHERE id=p_offer AND state='published_demo';
  IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM public.circle_v21_partners p WHERE p.id=o.partner_id AND p.state='published_demo') THEN
    RETURN jsonb_build_object('eligible_demo',false,'reason','Offer not available for demo verification');
  END IF;
  SELECT * INTO e FROM public.circle_v211_entitlements t
   WHERE t.user_id=p_user AND t.state='active_demo' AND t.starts_at<=now() AND t.ends_at>now()
   AND (
    (t.source_type='corporate' AND o.audience IN ('corporate','both') AND EXISTS (
      SELECT 1 FROM public.circle_v21_corporate_roster r WHERE r.user_id=p_user AND r.corporate_id=t.source_id AND r.state='linked_demo'))
    OR (t.source_type='individual' AND o.audience IN ('individual','both') AND EXISTS (
      SELECT 1 FROM public.circle_v21_lifestyle_interest i
      JOIN public.circle_v21_lifestyle_plans p ON p.id=i.plan_id
      WHERE i.user_id=p_user AND i.plan_id=t.source_id AND i.state='interested_demo' AND p.state='published_demo'))
   ) ORDER BY CASE WHEN t.source_type='corporate' THEN 0 ELSE 1 END, t.ends_at DESC LIMIT 1;
  IF NOT FOUND THEN RETURN jsonb_build_object('eligible_demo',false,'reason','No active demo entitlement for this offer'); END IF;
  RETURN jsonb_build_object('eligible_demo',true,'source_type',e.source_type,
    'expires_at',e.ends_at,'reason','SIMULATION ONLY · no real discount or payment rights');
END;$$;
REVOKE ALL ON FUNCTION public.circle_v211_eligibility_internal(uuid,uuid) FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION public.circle_v211_my_eligibility(p_offer_id uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path='' AS $$
BEGIN
 IF (SELECT auth.uid()) IS NULL THEN RAISE EXCEPTION 'Sign in required'; END IF;
 RETURN public.circle_v211_eligibility_internal((SELECT auth.uid()),p_offer_id);
END;$$;
REVOKE ALL ON FUNCTION public.circle_v211_my_eligibility(uuid) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.circle_v211_my_eligibility(uuid) TO authenticated;

CREATE OR REPLACE FUNCTION public.circle_v211_grant_demo(p_source_type text,p_source_id uuid,p_user_id uuid,p_days integer DEFAULT 30)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE v_id uuid;
BEGIN
 IF NOT public.circle_v21_is_founder() THEN RAISE EXCEPTION 'Founder only'; END IF;
 IF p_user_id IS NULL OR p_source_id IS NULL OR p_days NOT BETWEEN 1 AND 365 THEN RAISE EXCEPTION 'Invalid demo grant details'; END IF;
 IF p_source_type='corporate' THEN
   IF NOT EXISTS(SELECT 1 FROM public.circle_v21_corporate_roster r WHERE r.user_id=p_user_id AND r.corporate_id=p_source_id AND r.state='linked_demo') THEN
     RAISE EXCEPTION 'No existing test employee-company link'; END IF;
 ELSIF p_source_type='individual' THEN
   IF NOT EXISTS(SELECT 1 FROM public.circle_v21_lifestyle_interest i
      JOIN public.circle_v21_lifestyle_plans p ON p.id=i.plan_id
      WHERE i.user_id=p_user_id AND i.plan_id=p_source_id AND i.state='interested_demo' AND p.state='published_demo') THEN
     RAISE EXCEPTION 'No published plan and recorded interest for this test user'; END IF;
 ELSE RAISE EXCEPTION 'Unsupported demo source'; END IF;
 -- Existing active rows, even expired ones, must be revoked before another simulated grant.
 INSERT INTO public.circle_v211_entitlements(user_id,source_type,source_id,ends_at,created_by)
 VALUES(p_user_id,p_source_type,p_source_id,now()+make_interval(days=>p_days),(SELECT auth.uid())) RETURNING id INTO v_id;
 RETURN v_id;
END;$$;
REVOKE ALL ON FUNCTION public.circle_v211_grant_demo(text,uuid,uuid,integer) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.circle_v211_grant_demo(text,uuid,uuid,integer) TO authenticated;

CREATE OR REPLACE FUNCTION public.circle_v211_revoke_demo(p_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
BEGIN
 IF NOT public.circle_v21_is_founder() THEN RAISE EXCEPTION 'Founder only'; END IF;
 UPDATE public.circle_v211_entitlements SET state='revoked_demo',revoked_at=now()
 WHERE id=p_id AND state='active_demo';
 IF NOT FOUND THEN RAISE EXCEPTION 'Active demo grant not found'; END IF;
END;$$;
REVOKE ALL ON FUNCTION public.circle_v211_revoke_demo(uuid) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.circle_v211_revoke_demo(uuid) TO authenticated;

CREATE OR REPLACE FUNCTION public.circle_v211_assign_verifier(p_partner_id uuid,p_user_id uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE v_id uuid;
BEGIN
 IF NOT public.circle_v21_is_founder() THEN RAISE EXCEPTION 'Founder only'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.circle_v21_partners WHERE id=p_partner_id) THEN RAISE EXCEPTION 'Partner not found'; END IF;
 IF NOT EXISTS(SELECT 1 FROM auth.users WHERE id=p_user_id) THEN RAISE EXCEPTION 'Use an existing test account'; END IF;
 IF EXISTS(SELECT 1 FROM public.circle_founders WHERE user_id=p_user_id) THEN RAISE EXCEPTION 'Founder does not need verifier assignment'; END IF;
 INSERT INTO public.circle_v211_partner_verifiers(partner_id,user_id,created_by)
 VALUES (p_partner_id,p_user_id,(SELECT auth.uid())) RETURNING id INTO v_id;
 RETURN v_id;
END;$$;
REVOKE ALL ON FUNCTION public.circle_v211_assign_verifier(uuid,uuid) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.circle_v211_assign_verifier(uuid,uuid) TO authenticated;

CREATE OR REPLACE FUNCTION public.circle_v211_remove_verifier(p_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
BEGIN
 IF NOT public.circle_v21_is_founder() THEN RAISE EXCEPTION 'Founder only'; END IF;
 DELETE FROM public.circle_v211_partner_verifiers WHERE id=p_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'Verifier assignment not found'; END IF;
END;$$;
REVOKE ALL ON FUNCTION public.circle_v211_remove_verifier(uuid) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.circle_v211_remove_verifier(uuid) TO authenticated;

CREATE OR REPLACE FUNCTION public.circle_v211_issue_demo_code(p_offer_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE v_user uuid:=(SELECT auth.uid());v_offer public.circle_v21_offers%ROWTYPE;
        v_elig jsonb;v_code text;v_until timestamptz;
BEGIN
 IF v_user IS NULL THEN RAISE EXCEPTION 'Sign in required'; END IF;
 v_elig:=public.circle_v211_eligibility_internal(v_user,p_offer_id);
 IF NOT COALESCE((v_elig->>'eligible_demo')::boolean,false) THEN RAISE EXCEPTION 'No active DEMO entitlement for this offer'; END IF;
 IF EXISTS(SELECT 1 FROM public.circle_v211_demo_passes t WHERE t.user_id=v_user AND t.created_at>now()-interval '15 seconds') THEN
  RAISE EXCEPTION 'Please allow 15 seconds before creating another test code'; END IF;
 SELECT * INTO v_offer FROM public.circle_v21_offers WHERE id=p_offer_id;
 v_code:='D21-'||substr(replace(gen_random_uuid()::text,'-',''),1,24);
 v_until:=now()+interval '5 minutes';
 INSERT INTO public.circle_v211_demo_passes(user_id,partner_id,offer_id,token_hash,expires_at)
 VALUES(v_user,v_offer.partner_id,p_offer_id,md5(v_code),v_until);
 RETURN jsonb_build_object('demo_code',v_code,'expires_at',v_until,'offer_title',v_offer.title,
  'notice','SIMULATED VERIFICATION ONLY. Not a valid hotel discount.');
END;$$;
REVOKE ALL ON FUNCTION public.circle_v211_issue_demo_code(uuid) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.circle_v211_issue_demo_code(uuid) TO authenticated;

CREATE OR REPLACE FUNCTION public.circle_v211_verify_demo_code(p_code text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE v_caller uuid:=(SELECT auth.uid());v_pass public.circle_v211_demo_passes%ROWTYPE;
        v_offer public.circle_v21_offers%ROWTYPE;v_elig jsonb;v_partner text;
BEGIN
 IF v_caller IS NULL THEN RAISE EXCEPTION 'Sign in required'; END IF;
 IF p_code IS NULL OR p_code !~ '^D21-[0-9a-f]{24}$' THEN RAISE EXCEPTION 'Invalid demo verification code format'; END IF;
 SELECT * INTO v_pass FROM public.circle_v211_demo_passes
 WHERE token_hash=md5(p_code) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Demo code not found'; END IF;
 IF NOT public.circle_v21_is_founder() AND NOT EXISTS(
    SELECT 1 FROM public.circle_v211_partner_verifiers v
    WHERE v.partner_id=v_pass.partner_id AND v.user_id=v_caller) THEN
   RAISE EXCEPTION 'Not authorized to verify codes for this partner'; END IF;
 IF v_pass.user_id=v_caller THEN RAISE EXCEPTION 'Self-verification is not permitted'; END IF;
 IF v_pass.verified_at IS NOT NULL THEN RAISE EXCEPTION 'Demo code has already been used'; END IF;
 IF v_pass.expires_at<=now() THEN RAISE EXCEPTION 'Demo code has expired'; END IF;
 v_elig:=public.circle_v211_eligibility_internal(v_pass.user_id,v_pass.offer_id);
 IF NOT COALESCE((v_elig->>'eligible_demo')::boolean,false) THEN RAISE EXCEPTION 'Demo entitlement is no longer valid'; END IF;
 SELECT * INTO v_offer FROM public.circle_v21_offers WHERE id=v_pass.offer_id AND partner_id=v_pass.partner_id;
 SELECT p.name INTO v_partner FROM public.circle_v21_partners p WHERE p.id=v_pass.partner_id;
 UPDATE public.circle_v211_demo_passes SET verified_at=now(),verified_by=v_caller WHERE id=v_pass.id;
 RETURN jsonb_build_object('result','DEMO VERIFIED · NOT REDEEMABLE','partner',v_partner,
  'offer',v_offer.title,'illustrative_discount_pct',v_offer.discount_pct,
  'simulated_source',v_elig->>'source_type','verified_at',now(),
  'notice','No money, discount, booking or real partner benefit was processed.');
END;$$;
REVOKE ALL ON FUNCTION public.circle_v211_verify_demo_code(text) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.circle_v211_verify_demo_code(text) TO authenticated;

COMMIT;

-- IMPORTANT: Test with separate authenticated Founder, member, manager, and unassigned
-- user accounts. The Supabase SQL Editor runs as a high-privilege database account;
-- it does not prove the actual per-user RLS behavior. Do NOT use real hotel discounts.
