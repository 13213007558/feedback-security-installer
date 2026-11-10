import pytest
from installer.policies import (
    PTH_BLANK,
    PTH_COMMENT,
    PTH_IMPORT,
    PTH_PATH,
    EntryCategory,
    LaunchEntry,
    LaunchEntryPolicy,
    PolicyAction,
    PolicyRule,
    PolicyViolation,
    classify_pth_line,
    is_pth_launch_file,
    load_launch_entry_policy,
    policy_from_dict,
)


def make_entry(
    category=EntryCategory.ENTRY_POINT,
    *,
    name="fancy",
    module="fancy:main",
    source_path="fancy-1.0.0.dist-info/entry_points.txt",
    scheme="scripts",
    destination_path="fancy",
    archive="fancy-1.0.0-py3-none-any.whl",
    line_numbers=(),
):
    return LaunchEntry(
        category=category,
        archive=archive,
        source_path=source_path,
        scheme=scheme,
        destination_path=destination_path,
        name=name,
        module=module,
        line_numbers=line_numbers,
    )


class TestClassifyPthLine:
    @pytest.mark.parametrize(
        ("line", "kind"),
        [
            ("# a comment", PTH_COMMENT),
            ("\t# not a comment for site, but a path", PTH_PATH),
            ("", PTH_BLANK),
            ("   \t", PTH_BLANK),
            ("import os", PTH_IMPORT),
            ("import\tos", PTH_IMPORT),
            ("/some/where", PTH_PATH),
            ("  import os", PTH_PATH),
            ("#import os", PTH_COMMENT),
            ("importable", PTH_PATH),
        ],
    )
    def test_classification_matches_site_semantics(self, line, kind):
        assert classify_pth_line(line) == kind


class TestIsPthLaunchFile:
    @pytest.mark.parametrize(
        "path",
        [
            "foo.pth",
            "foo.PTH",
            "Foo.Pth",
        ],
    )
    def test_site_root_pth_files_are_launch_files(self, path):
        assert is_pth_launch_file(path)

    @pytest.mark.parametrize(
        "path",
        [
            "pkg/foo.pth",
            ".hidden.pth",
            "foo.txt",
            "data/foo.pth",
            "headers/foo.pth",
        ],
    )
    def test_other_files_are_not_launch_files(self, path):
        assert not is_pth_launch_file(path)


class TestPolicyRule:
    def test_empty_selectors_match_everything(self):
        rule = PolicyRule(action=PolicyAction.ALLOW)
        assert rule.matches(make_entry())
        assert rule.matches(make_entry(category=EntryCategory.PTH_IMPORT, module=None))

    def test_category_selector(self):
        rule = PolicyRule(
            action=PolicyAction.ALLOW,
            categories=(EntryCategory.ENTRY_POINT,),
        )
        assert rule.matches(make_entry(category=EntryCategory.ENTRY_POINT))
        assert not rule.matches(make_entry(category=EntryCategory.SCRIPT))

    def test_name_selector_is_case_insensitive(self):
        rule = PolicyRule(action=PolicyAction.ALLOW, names=("Fancy",))
        assert rule.matches(make_entry(name="fancy"))
        assert not rule.matches(make_entry(name="other"))

    def test_module_selector_requires_module_target(self):
        rule = PolicyRule(action=PolicyAction.ALLOW, modules=("fancy:main",))
        assert rule.matches(make_entry(module="fancy:main"))
        assert not rule.matches(make_entry(module="fancy:other"))
        assert not rule.matches(make_entry(module=None))

    def test_all_selectors_must_apply(self):
        rule = PolicyRule(
            action=PolicyAction.ALLOW,
            categories=(EntryCategory.ENTRY_POINT,),
            names=("fancy",),
            modules=("fancy:main",),
        )
        assert rule.matches(make_entry())
        assert not rule.matches(make_entry(name="other"))
        assert not rule.matches(make_entry(module="fancy:other"))


class TestLaunchEntryPolicy:
    def test_first_matching_rule_wins(self):
        policy = LaunchEntryPolicy(
            default_action=PolicyAction.DENY,
            rules=(
                PolicyRule(
                    PolicyAction.DENY,
                    categories=(EntryCategory.ENTRY_POINT,),
                ),
                PolicyRule(PolicyAction.ALLOW, names=("fancy",)),
            ),
        )
        action, reason = policy.decide(make_entry())
        assert action is PolicyAction.DENY
        assert "rule 1" in reason

    def test_default_action_used_when_nothing_matches(self):
        policy = LaunchEntryPolicy(default_action=PolicyAction.ALLOW)
        action, reason = policy.decide(make_entry())
        assert action is PolicyAction.ALLOW
        assert "default action" in reason

    def test_evaluate_allows_when_all_entries_allowed(self):
        policy = LaunchEntryPolicy(default_action=PolicyAction.ALLOW)
        policy.evaluate(
            [
                make_entry(name="fancy"),
                make_entry(name="other", destination_path="other"),
            ]
        )

    def test_evaluate_denies_and_reports_archive_and_destination(self):
        entry = make_entry()
        policy = LaunchEntryPolicy(default_action=PolicyAction.DENY)
        with pytest.raises(PolicyViolation) as ctx:
            policy.evaluate([entry])

        message = str(ctx.value)
        assert entry.archive in message
        assert entry.source_path in message
        assert "scripts:fancy" in message
        assert ctx.value.violations[0][0] is entry

    def test_evaluate_collects_every_violation(self):
        policy = LaunchEntryPolicy(default_action=PolicyAction.DENY)
        with pytest.raises(PolicyViolation) as ctx:
            policy.evaluate([make_entry(name="one"), make_entry(name="two")])
        assert len(ctx.value.violations) == 2

    def test_evaluate_rejects_case_insensitive_destination_collisions(self):
        policy = LaunchEntryPolicy(default_action=PolicyAction.ALLOW)
        first = make_entry(name="fancy", destination_path="fancy")
        second = make_entry(
            name="FANCY",
            destination_path="FANCY",
            source_path="fancy-1.0.0.data/scripts/FANCY",
        )
        with pytest.raises(PolicyViolation) as ctx:
            policy.evaluate([first, second])
        assert "duplicate final destination" in str(ctx.value)

    def test_distinct_destinations_are_not_collisions(self):
        policy = LaunchEntryPolicy(default_action=PolicyAction.ALLOW)
        policy.evaluate(
            [
                make_entry(name="fancy", destination_path="fancy"),
                make_entry(
                    name="fancy-gui",
                    destination_path="fancy-gui",
                    source_path="fancy-1.0.0.dist-info/entry_points.txt",
                ),
            ]
        )


class TestPolicyFromDict:
    def test_builds_policy_from_mapping(self):
        policy = policy_from_dict(
            {
                "default_action": "deny",
                "rules": [
                    {
                        "action": "allow",
                        "categories": ["entry_point"],
                        "names": ["fancy", "fancy-gui"],
                        "modules": ["fancy:main"],
                    }
                ],
            }
        )
        assert policy.default_action is PolicyAction.DENY
        rule = policy.rules[0]
        assert rule.action is PolicyAction.ALLOW
        assert rule.categories == (EntryCategory.ENTRY_POINT,)
        assert rule.names == ("fancy", "fancy-gui")
        assert rule.modules == ("fancy:main",)

    def test_optional_rule_fields_default_to_empty(self):
        policy = policy_from_dict(
            {"default_action": "allow", "rules": [{"action": "deny"}]}
        )
        rule = policy.rules[0]
        assert rule.categories == ()
        assert rule.names == ()
        assert rule.modules == ()

    def test_rules_default_to_empty_list(self):
        policy = policy_from_dict({"default_action": "allow"})
        assert policy.rules == ()

    @pytest.mark.parametrize(
        "data",
        [
            [],
            {"default_action": "maybe"},
            {"default_action": "deny", "rules": {}},
            {"default_action": "deny", "rules": ["no"]},
            {"default_action": "deny", "rules": [{"action": "maybe"}]},
            {
                "default_action": "deny",
                "rules": [{"action": "allow", "categories": "x"}],
            },
            {
                "default_action": "deny",
                "rules": [{"action": "allow", "categories": [1]}],
            },
            {
                "default_action": "deny",
                "rules": [{"action": "allow", "names": "x"}],
            },
            {
                "default_action": "deny",
                "rules": [{"action": "allow", "names": [1]}],
            },
            {
                "default_action": "deny",
                "rules": [{"action": "allow", "modules": "x"}],
            },
            {
                "default_action": "deny",
                "rules": [{"action": "allow", "modules": [1]}],
            },
            {
                "default_action": "deny",
                "rules": [{"action": "allow", "categories": {}}],
            },
        ],
    )
    def test_invalid_configuration_raises_value_error(self, data):
        with pytest.raises(ValueError):
            policy_from_dict(data)

    def test_non_string_default_action_raises_value_error(self):
        with pytest.raises(ValueError, match="default_action must be a string"):
            policy_from_dict({"default_action": 1})

    def test_error_message_lists_allowed_values(self):
        with pytest.raises(ValueError, match="pth_path"):
            policy_from_dict(
                {
                    "default_action": "deny",
                    "rules": [{"action": "allow", "categories": ["nope"]}],
                }
            )


class TestLoadLaunchEntryPolicy:
    def test_loads_policy_from_json_file(self, tmp_path):
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(
            '{"default_action": "deny", "rules": ['
            '{"action": "allow", "categories": ["script"]}]}',
            encoding="utf-8",
        )

        policy = load_launch_entry_policy(policy_path)

        assert policy.default_action is PolicyAction.DENY
        assert policy.rules[0].categories == (EntryCategory.SCRIPT,)

    def test_invalid_json_raises_value_error(self, tmp_path):
        policy_path = tmp_path / "policy.json"
        policy_path.write_text("{not json", encoding="utf-8")

        with pytest.raises(ValueError):
            load_launch_entry_policy(policy_path)
