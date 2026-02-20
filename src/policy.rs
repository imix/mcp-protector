//! Policy enforcement engine.
//!
//! Applies the tool allowlist to incoming MCP `tools/call` and `tools/list`
//! requests.  All functions are pure — no state, no I/O, no `async`.  This
//! makes them deterministic, independently testable, and provably correct with
//! 100% branch coverage enforced by CI (NFR-M2, NFR-C1, NFR-C2, NFR-S3).
//!
//! # Allowlist semantics
//!
//! - Matching is byte-for-byte exact and case-sensitive (NFR-C1).
//! - An empty allowlist blocks every tool call (FR8).
//! - `filter_tools_list` returns the *intersection* of the upstream tool list
//!   and the allowlist — tools listed in the allowlist but not offered by the
//!   upstream are excluded from the result (NFR-C3).

use std::collections::HashSet;

use rmcp::model::Tool;

/// Return `true` if `tool_name` is present in the allowlist, `false` otherwise.
///
/// Matching is byte-for-byte exact and case-sensitive (NFR-C1).  An empty
/// `allowlist` always returns `false` (FR8).
#[must_use]
pub fn is_tool_allowed(tool_name: &str, allowlist: &HashSet<String>) -> bool {
    allowlist.contains(tool_name)
}

/// Filter `tools` to the intersection of the upstream list and `allowlist`.
///
/// A tool is included in the result only when its name appears in **both** the
/// upstream-provided list *and* the configured allowlist.  Tools present in the
/// allowlist but absent from `tools` are silently excluded (NFR-C3).
#[must_use]
pub fn filter_tools_list(tools: Vec<Tool>, allowlist: &HashSet<String>) -> Vec<Tool> {
    tools
        .into_iter()
        .filter(|t| allowlist.contains(t.name.as_ref()))
        .collect()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use serde_json::Map;

    use super::*;

    fn allowlist(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    fn make_tool(name: &str) -> Tool {
        Tool {
            name: Cow::Owned(name.to_owned()),
            title: None,
            description: None,
            input_schema: Arc::new(Map::new()),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        }
    }

    // ── is_tool_allowed ───────────────────────────────────────────────────────

    #[test]
    fn allows_listed_tool_name() {
        let allow = allowlist(&["read_file"]);
        assert!(is_tool_allowed("read_file", &allow));
    }

    #[test]
    fn blocks_unlisted_tool_name() {
        let allow = allowlist(&["read_file"]);
        assert!(!is_tool_allowed("execute_sql", &allow));
    }

    #[test]
    fn empty_allowlist_blocks_all() {
        let allow = allowlist(&[]);
        assert!(!is_tool_allowed("any_tool", &allow));
    }

    #[test]
    fn case_sensitive_match_rejects_different_case() {
        // "Read_File" ≠ "read_file" — byte-for-byte comparison (NFR-C1)
        let allow = allowlist(&["Read_File"]);
        assert!(!is_tool_allowed("read_file", &allow));
    }

    // ── filter_tools_list ─────────────────────────────────────────────────────

    #[test]
    fn filter_returns_intersection_only() {
        // Upstream: read_file, execute_sql, delete_table
        // Allowlist: read_file, list_dir
        // Expected result: [read_file]  (list_dir absent from upstream; others not in allowlist)
        let upstream = vec![
            make_tool("read_file"),
            make_tool("execute_sql"),
            make_tool("delete_table"),
        ];
        let allow = allowlist(&["read_file", "list_dir"]);
        let result = filter_tools_list(upstream, &allow);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name.as_ref(), "read_file");
    }

    #[test]
    fn filter_excludes_tools_not_in_allowlist() {
        let upstream = vec![make_tool("dangerous_tool"), make_tool("safe_tool")];
        let allow = allowlist(&["safe_tool"]);
        let result = filter_tools_list(upstream, &allow);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name.as_ref(), "safe_tool");
    }

    #[test]
    fn filter_with_empty_allowlist_returns_empty() {
        let upstream = vec![make_tool("read_file"), make_tool("write_file")];
        let allow = allowlist(&[]);
        let result = filter_tools_list(upstream, &allow);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_with_empty_upstream_returns_empty() {
        let allow = allowlist(&["read_file"]);
        let result = filter_tools_list(vec![], &allow);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_allowlist_only_tool_absent_from_upstream_excluded() {
        // "list_dir" is in allowlist but NOT upstream — must not appear in result
        let upstream = vec![make_tool("read_file")];
        let allow = allowlist(&["read_file", "list_dir"]);
        let result = filter_tools_list(upstream, &allow);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name.as_ref(), "read_file");
        assert!(!result.iter().any(|t| t.name.as_ref() == "list_dir"));
    }
}
