//! Dependency graph built from an ingested npm lockfile.
//!
//! Resolution follows Node's `node_modules` walk: a dependency is looked up
//! in the requiring package's own `node_modules`, then in each parent. Cycles
//! are recorded and do not abort the build.

use crate::ingest::Lockfile;
use std::collections::BTreeMap;

/// Why an edge exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DepKind {
    /// `dependencies`.
    Prod,
    /// `devDependencies`.
    Dev,
    /// `optionalDependencies`.
    Optional,
    /// `peerDependencies`.
    Peer,
}

/// Resolved package graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Graph {
    /// Nodes in lockfile path order.
    pub nodes: Vec<Node>,
    /// Edges in a stable order: source path, then kind, then requested name.
    pub edges: Vec<Edge>,
    /// Dependencies whose target was not present in the lockfile.
    pub unresolved: Vec<Unresolved>,
    /// Back-edge cycles. Each path repeats its first node at the end.
    pub cycles: Vec<Cycle>,
}

/// One package in the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Index into [`Graph::nodes`].
    pub index: usize,
    /// Lockfile path. Empty for the root project.
    pub package_path: String,
    /// Package name.
    pub name: String,
    /// Locked version.
    pub version: String,
    /// True when the root project depends on this package directly.
    pub direct: bool,
    /// True when this node is reachable from the root, including the root itself.
    pub reachable: bool,
    /// Copied from the lockfile `dev` flag.
    pub dev_only: bool,
}

/// A resolved dependency edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    /// Source node index.
    pub from: usize,
    /// Target node index.
    pub to: usize,
    /// Requested package name (the key in the manifest).
    pub name: String,
    /// Requested version range.
    pub spec: String,
    /// Manifest section the edge came from.
    pub kind: DepKind,
}

/// A dependency that could not be placed in the lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    /// Source node index.
    pub from: usize,
    /// Requested package name.
    pub name: String,
    /// Requested version range.
    pub spec: String,
    /// Manifest section the request came from.
    pub kind: DepKind,
}

/// A cycle expressed as node indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cycle {
    /// Indexes along the cycle, with the repeated start node at the end.
    pub nodes: Vec<usize>,
}

/// Build the dependency graph for `lock`.
///
/// Cycles and missing targets are data, not failures.
#[must_use]
pub fn resolve(lock: &Lockfile) -> Graph {
    let mut nodes = Vec::with_capacity(lock.packages.len());
    let mut by_path = BTreeMap::new();
    for (index, package) in lock.packages.iter().enumerate() {
        by_path.insert(package.path.as_str(), index);
        nodes.push(Node {
            index,
            package_path: package.path.clone(),
            name: package.name.clone(),
            version: package.version.clone(),
            direct: false,
            reachable: false,
            dev_only: package.dev,
        });
    }

    let root_index = nodes.iter().position(|node| node.package_path.is_empty());
    let mut edges = Vec::new();
    let mut unresolved = Vec::new();

    for package in &lock.packages {
        let Some(&from) = by_path.get(package.path.as_str()) else {
            continue;
        };
        let groups = [
            (DepKind::Prod, &package.dependencies),
            (DepKind::Dev, &package.dev_dependencies),
            (DepKind::Optional, &package.optional_dependencies),
            (DepKind::Peer, &package.peer_dependencies),
        ];
        for (kind, deps) in groups {
            for (name, spec) in deps {
                match lookup(&by_path, &package.path, name) {
                    Some(to) => {
                        if root_index == Some(from) {
                            nodes[to].direct = true;
                        }
                        edges.push(Edge {
                            from,
                            to,
                            name: name.clone(),
                            spec: spec.clone(),
                            kind,
                        });
                    }
                    None => unresolved.push(Unresolved {
                        from,
                        name: name.clone(),
                        spec: spec.clone(),
                        kind,
                    }),
                }
            }
        }
    }

    let cycles = find_cycles(nodes.len(), &edges);
    if let Some(root) = root_index {
        mark_reachable(root, &edges, &mut nodes);
    }

    Graph {
        nodes,
        edges,
        unresolved,
        cycles,
    }
}

fn lookup(by_path: &BTreeMap<&str, usize>, from_path: &str, name: &str) -> Option<usize> {
    let mut cursor = from_path;
    loop {
        let candidate = if cursor.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{cursor}/node_modules/{name}")
        };
        if let Some(&index) = by_path.get(candidate.as_str()) {
            return Some(index);
        }
        if cursor.is_empty() {
            return None;
        }
        cursor = parent_path(cursor);
    }
}

fn parent_path(path: &str) -> &str {
    match path.rfind('/') {
        Some(index) => &path[..index],
        None => "",
    }
}

fn mark_reachable(root: usize, edges: &[Edge], nodes: &mut [Node]) {
    let mut adjacency = vec![Vec::new(); nodes.len()];
    for edge in edges {
        adjacency[edge.from].push(edge.to);
    }
    let mut stack = vec![root];
    let mut seen = vec![false; nodes.len()];
    seen[root] = true;
    nodes[root].reachable = true;
    while let Some(current) = stack.pop() {
        for &next in &adjacency[current] {
            if !seen[next] {
                seen[next] = true;
                nodes[next].reachable = true;
                stack.push(next);
            }
        }
    }
}

fn find_cycles(node_count: usize, edges: &[Edge]) -> Vec<Cycle> {
    let mut adjacency = vec![Vec::new(); node_count];
    for edge in edges {
        adjacency[edge.from].push(edge.to);
    }

    const WHITE: u8 = 0;
    let mut color = vec![WHITE; node_count];
    let mut stack = Vec::new();
    let mut cycles = Vec::new();

    for start in 0..node_count {
        if color[start] == WHITE {
            visit(start, &adjacency, &mut color, &mut stack, &mut cycles);
        }
    }
    cycles.sort_by(|left, right| left.nodes.cmp(&right.nodes));
    cycles
}

fn visit(
    start: usize,
    adjacency: &[Vec<usize>],
    color: &mut [u8],
    stack: &mut Vec<usize>,
    cycles: &mut Vec<Cycle>,
) {
    const WHITE: u8 = 0;
    const GRAY: u8 = 1;
    const BLACK: u8 = 2;
    color[start] = GRAY;
    stack.push(start);
    for &next in &adjacency[start] {
        match color[next] {
            GRAY => {
                if let Some(position) = stack.iter().position(|&node| node == next) {
                    let mut path = stack[position..].to_vec();
                    path.push(next);
                    cycles.push(Cycle { nodes: path });
                }
            }
            WHITE => visit(next, adjacency, color, stack, cycles),
            _ => {}
        }
    }
    stack.pop();
    color[start] = BLACK;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::parse_lockfile_str;
    use std::fs;
    use std::path::Path;

    fn fixture(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/resolve")
            .join(name);
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
    }

    fn edge<'a>(graph: &'a Graph, from: &str, to: &str) -> &'a Edge {
        graph
            .edges
            .iter()
            .find(|edge| {
                graph.nodes[edge.from].package_path == from
                    && graph.nodes[edge.to].package_path == to
            })
            .unwrap_or_else(|| panic!("missing edge {from} -> {to}"))
    }

    #[test]
    fn nested_resolution_marks_direct_and_transitive() {
        let lock = parse_lockfile_str(&fixture("nested.json"), "nested.json").unwrap();
        let graph = resolve(&lock);

        let root_foo = edge(&graph, "", "node_modules/foo");
        assert_eq!(root_foo.kind, DepKind::Prod);
        assert!(graph.nodes[root_foo.to].direct);

        let root_bar = edge(&graph, "", "node_modules/bar");
        assert_eq!(graph.nodes[root_bar.to].version, "1.5.0");
        assert!(graph.nodes[root_bar.to].direct);

        let foo_bar = edge(
            &graph,
            "node_modules/foo",
            "node_modules/foo/node_modules/bar",
        );
        assert_eq!(graph.nodes[foo_bar.to].version, "2.0.0");
        assert!(!graph.nodes[foo_bar.to].direct);
        assert!(graph.nodes[foo_bar.to].reachable);

        let foo_react = edge(&graph, "node_modules/foo", "node_modules/react");
        assert_eq!(foo_react.kind, DepKind::Peer);
        assert!(!graph.nodes[foo_react.to].direct);
        assert!(graph.nodes[foo_react.to].reachable);

        let fsevents = graph
            .nodes
            .iter()
            .find(|node| node.name == "fsevents")
            .unwrap();
        assert!(fsevents.direct);
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| { edge.to == fsevents.index && edge.kind == DepKind::Optional })
        );

        let orphan = graph
            .nodes
            .iter()
            .find(|node| node.name == "orphan")
            .unwrap();
        assert!(!orphan.direct);
        assert!(!orphan.reachable);
        assert!(graph.cycles.is_empty());
    }

    #[test]
    fn cycles_are_recorded_without_aborting() {
        let lock = parse_lockfile_str(&fixture("cycle.json"), "cycle.json").unwrap();
        let graph = resolve(&lock);
        assert_eq!(graph.cycles.len(), 1);
        let names: Vec<_> = graph.cycles[0]
            .nodes
            .iter()
            .map(|&index| graph.nodes[index].name.as_str())
            .collect();
        assert_eq!(names, ["a", "b", "a"]);

        let c = graph.nodes.iter().find(|node| node.name == "c").unwrap();
        assert!(c.direct);
        assert!(c.reachable);
        let b = graph.nodes.iter().find(|node| node.name == "b").unwrap();
        assert!(!b.direct);
        assert!(b.reachable);
    }

    #[test]
    fn missing_target_is_unresolved() {
        let lock = parse_lockfile_str(
            r#"{
              "name": "app",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "packages": {
                "": {
                  "name": "app",
                  "version": "1.0.0",
                  "dependencies": { "missing": "^1.0.0" }
                }
              }
            }"#,
            "missing.json",
        )
        .unwrap();
        let graph = resolve(&lock);
        assert!(graph.edges.is_empty());
        assert_eq!(graph.unresolved.len(), 1);
        assert_eq!(graph.unresolved[0].name, "missing");
        assert_eq!(graph.unresolved[0].kind, DepKind::Prod);
        assert!(graph.cycles.is_empty());
    }

    #[test]
    fn repeated_resolve_is_identical() {
        let lock = parse_lockfile_str(&fixture("cycle.json"), "cycle.json").unwrap();
        assert_eq!(resolve(&lock), resolve(&lock));
    }
}
