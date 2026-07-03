//! A domain-suffix matcher backed by a label trie, not raw string
//! suffix comparison. `str::ends_with` is unsafe for this: `"evilgithub.com"
//! .ends_with("github.com")` is `true`, which would let an attacker-owned
//! domain slip past a rule meant for `github.com`. Matching label-by-label
//! from the TLD inward closes that off, and also rejects the mirror-image
//! trick of appending a trusted suffix as a prefix
//! (`"github.com.attacker.net"`).

use std::collections::HashMap;

#[derive(Debug, Default)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    /// This node is the end of a registered domain — matches the domain
    /// itself and, since lookups keep walking past a match, every
    /// subdomain of it too.
    terminal: bool,
}

#[derive(Debug, Default)]
pub struct DomainSuffixTrie {
    root: TrieNode,
}

impl DomainSuffixTrie {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, domain: &str) {
        let mut node = &mut self.root;
        for label in Self::reversed_labels(domain) {
            node = node.children.entry(label).or_default();
        }
        node.terminal = true;
    }

    /// True if `domain` is exactly a registered domain, or a subdomain of
    /// one.
    pub fn matches(&self, domain: &str) -> bool {
        let mut node = &self.root;
        for label in Self::reversed_labels(domain) {
            match node.children.get(&label) {
                Some(next) => {
                    node = next;
                    if node.terminal {
                        return true;
                    }
                }
                None => return false,
            }
        }
        false
    }

    /// Domain labels, TLD first, lowercased (DNS names are
    /// case-insensitive) and with a trailing root dot stripped.
    fn reversed_labels(domain: &str) -> Vec<String> {
        domain
            .trim_end_matches('.')
            .to_ascii_lowercase()
            .rsplit('.')
            .map(str::to_string)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_registered_domain_itself() {
        let mut trie = DomainSuffixTrie::new();
        trie.insert("github.com");
        assert!(trie.matches("github.com"));
    }

    #[test]
    fn matches_a_subdomain() {
        let mut trie = DomainSuffixTrie::new();
        trie.insert("github.com");
        assert!(trie.matches("api.github.com"));
        assert!(trie.matches("raw.githubusercontent.com.github.com"));
    }

    #[test]
    fn does_not_match_a_domain_that_merely_shares_a_string_suffix() {
        let mut trie = DomainSuffixTrie::new();
        trie.insert("github.com");
        assert!(!trie.matches("evilgithub.com"));
        assert!(!trie.matches("notgithub.com"));
    }

    #[test]
    fn does_not_match_the_trusted_suffix_used_as_an_attacker_prefix() {
        let mut trie = DomainSuffixTrie::new();
        trie.insert("github.com");
        assert!(!trie.matches("github.com.attacker.net"));
    }

    #[test]
    fn does_not_match_an_unrelated_domain() {
        let mut trie = DomainSuffixTrie::new();
        trie.insert("github.com");
        assert!(!trie.matches("example.com"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let mut trie = DomainSuffixTrie::new();
        trie.insert("GitHub.COM");
        assert!(trie.matches("api.github.com"));
    }

    #[test]
    fn empty_trie_matches_nothing() {
        let trie = DomainSuffixTrie::new();
        assert!(!trie.matches("github.com"));
    }
}
