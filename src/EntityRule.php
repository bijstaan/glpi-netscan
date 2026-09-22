<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;
use Rule;
use RuleAction;
use RuleCriteria;
use RuleImportEntity;

/**
 * Routes what a scanner imports into the scanner's entity.
 *
 * An asset imported through core's inventory pipeline gets its entity from the
 * entity rules and nothing else (Glpi\Inventory\MainAsset\MainAsset::handle).
 * When no rule matches, it goes to the inventory configuration's default
 * entity, which is the root on a stock install. The active entity in the
 * session plays no part in that decision. A scanner enrolled into a customer's
 * entity therefore filed that customer's switches and printers in the root,
 * with no error to say why. Phones and PDUs never had the problem: the plugin
 * creates them itself, in the scanner's entity.
 *
 * The inventory tag is the one entity-rule criterion the plugin controls. Every
 * submission carries its scanner's tag, and this class keeps an ordinary rule
 * that maps the tag to the scanner's entity. The rule appears under
 * Administration > Rules > Rules for assigning an item to an entity, which is
 * where an administrator would look to find out why an asset landed where it
 * did. The osquery plugin does the same thing for its enrolment secrets.
 */
final class EntityRule
{
    /**
     * The inventory tag carried by everything this scanner submits.
     *
     * Derived from the id rather than the name, so renaming a scanner does not
     * orphan its rule.
     */
    public static function tagFor(int $scanners_id): ?string
    {
        return $scanners_id > 0 ? 'nsc-' . $scanners_id : null;
    }

    /** The rule uuid this plugin owns for a scanner, which is also how it finds it again. */
    private static function ruleUuid(int $scanners_id): string
    {
        return 'glpinetscan-scanner-' . $scanners_id;
    }

    /**
     * Keep the rule for a scanner in step with the scanner's entity.
     *
     * The rule is appended rather than put first. Entity rules stop at the
     * first match, and jumping ahead of rules an administrator wrote is not
     * this plugin's call. A scanner in the root entity gets no rule, because
     * the root is already where an unmatched inventory lands. If it had a rule
     * from an earlier entity, that rule is dropped.
     *
     * @param array<string,mixed> $scanner a scanner row
     */
    public static function sync(array $scanner): void
    {
        $id          = (int) ($scanner['id'] ?? 0);
        $entities_id = (int) ($scanner['entities_id'] ?? 0);
        $tag         = self::tagFor($id);

        if ($tag === null) {
            return;
        }

        if ($entities_id <= 0) {
            self::drop($id);
            return;
        }

        $existing = self::ruleIdFor($id);
        if ($existing !== null) {
            // The scanner's entity is the source of truth, so only the rule's
            // action is corrected. Anything else an administrator changed about
            // the rule stays as they left it.
            self::setAction($existing, $entities_id, (int) ($scanner['is_recursive'] ?? 0));
            return;
        }

        $rules_id = (new RuleImportEntity())->add([
            'name'        => sprintf(
                __('Network scanner: %s', 'glpinetscan'),
                (string) ($scanner['name'] ?? '') !== '' ? (string) $scanner['name'] : $tag
            ),
            'sub_type'    => RuleImportEntity::class,
            'match'       => 'AND',
            'is_active'   => 1,
            'entities_id' => 0,
            'uuid'        => self::ruleUuid($id),
            'comment'     => __('Created by the network scanner plugin, so that devices this scanner reports are imported into the scanner\'s entity. If you delete it, they go to the default entity instead.', 'glpinetscan'),
        ]);

        if (!$rules_id) {
            return;
        }

        (new RuleCriteria())->add([
            'rules_id'  => $rules_id,
            'criteria'  => 'tag',
            'condition' => Rule::PATTERN_IS,
            'pattern'   => $tag,
        ]);

        self::setAction((int) $rules_id, $entities_id, (int) ($scanner['is_recursive'] ?? 0));
    }

    /** Point a rule's actions at an entity, replacing whatever they said before. */
    private static function setAction(int $rules_id, int $entities_id, int $is_recursive): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $action = new RuleAction();

        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => RuleAction::getTable(),
                'WHERE'  => ['rules_id' => $rules_id, 'field' => ['entities_id', 'is_recursive']],
            ]) as $row
        ) {
            $action->delete(['id' => (int) $row['id']]);
        }

        $action->add([
            'rules_id'    => $rules_id,
            'action_type' => 'assign',
            'field'       => 'entities_id',
            'value'       => $entities_id,
        ]);

        $action->add([
            'rules_id'    => $rules_id,
            'action_type' => 'assign',
            'field'       => 'is_recursive',
            'value'       => $is_recursive > 0 ? 1 : 0,
        ]);
    }

    /** The id of the rule this plugin created for a scanner, if it still exists. */
    public static function ruleIdFor(int $scanners_id): ?int
    {
        /** @var DBmysql $DB */
        global $DB;

        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => Rule::getTable(),
                'WHERE'  => ['uuid' => self::ruleUuid($scanners_id), 'sub_type' => RuleImportEntity::class],
                'LIMIT'  => 1,
            ]) as $row
        ) {
            return (int) $row['id'];
        }

        return null;
    }

    /**
     * Drop the rule for a scanner.
     *
     * Used when a scanner is purged, when it moves to the root entity, and on
     * uninstall. A rule matching a tag that nothing sends any more only
     * confuses whoever reads the rule list next.
     */
    public static function drop(int $scanners_id): void
    {
        $rules_id = self::ruleIdFor($scanners_id);
        if ($rules_id !== null) {
            (new RuleImportEntity())->delete(['id' => $rules_id], true);
        }
    }
}
