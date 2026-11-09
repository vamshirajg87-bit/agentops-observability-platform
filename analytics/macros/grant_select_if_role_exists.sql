{#
    grant_select_if_role_exists(relation, role)

    A post-hook statement: GRANT SELECT ON <relation> TO <role>, issued only
    when <role> exists.

    Why it is conditional.  On an empty database the models are built before
    the migration that creates the role, and that migration in turn grants on
    these models.  An unconditional GRANT therefore makes a first build
    impossible.  With the check, the first build succeeds without the role;
    the migration then creates the role and grants on the existing tables;
    and every later build re-grants on the rebuilt table, exactly as the
    unconditional statement did.

    What it does not do.  It never creates a role, never grants to PUBLIC,
    grants nothing but SELECT on the one relation it is given, and does not
    catch errors: a GRANT that fails for any other reason still fails the
    model.

    role must be a plain lower-case identifier; anything else stops the
    build before a statement is sent.
#}
{% macro grant_select_if_role_exists(relation, role) %}
    {%- if not modules.re.fullmatch('[a-z_][a-z0-9_]*', role) -%}
        {{ exceptions.raise_compiler_error(
            "grant_select_if_role_exists: role must be a plain identifier"
        ) }}
    {%- endif -%}
    DO $grant$
    BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{{ role }}') THEN
            EXECUTE 'GRANT SELECT ON {{ relation }} TO {{ role }}';
        END IF;
    END
    $grant$
{% endmacro %}
