-- better-auth-scim-provisioning 1.0 (its docs/upgrading.md): group links say which group they are
-- in their own columns and are found by organization through an index; links say whether the
-- account was adopted. Rows written by 0.3 keep working and gain the values when next updated.
ALTER TABLE scim_provisioning_group_links ADD COLUMN kind TEXT;
ALTER TABLE scim_provisioning_group_links ADD COLUMN subject_id TEXT;
CREATE INDEX IF NOT EXISTS scim_provisioning_group_links_org_idx ON scim_provisioning_group_links (organization_id);
ALTER TABLE scim_provisioning_links ADD COLUMN adopted INTEGER;
