//! The encrypted directory index.
//!
//! This is the only place file names, sizes, timestamps and the folder tree
//! exist. It is serialised to JSON, sealed with the index subkey and written
//! into the container, so inspecting a `.vault` reveals none of it -- not a
//! name, not an extension, not the number of files.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};

/// Id of the root folder. Ids are never reused within a vault.
pub const ROOT_ID: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
    Dir,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: u64,
    pub parent: u64,
    pub name: String,
    pub kind: NodeKind,

    /// Plaintext size in bytes. Zero for folders.
    #[serde(default)]
    pub size: u64,
    /// Absolute offset of the chunk stream inside the container.
    #[serde(default)]
    pub offset: u64,
    /// Ciphertext length of the chunk stream, tags included.
    #[serde(default)]
    pub enc_len: u64,
    /// The 19-byte STREAM nonce for this file, unique per stored file.
    #[serde(default)]
    pub nonce: Vec<u8>,

    /// Modification time, seconds since the Unix epoch, when the source
    /// filesystem reported one.
    #[serde(default)]
    pub mtime: Option<i64>,
}

impl Node {
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, NodeKind::Dir)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultIndex {
    /// Display name. Also the folder name used when exporting the whole vault.
    pub vault_name: String,
    pub created_at: i64,
    pub next_id: u64,
    pub nodes: Vec<Node>,
}

impl VaultIndex {
    pub fn new(vault_name: &str, created_at: i64) -> Self {
        let root = Node {
            id: ROOT_ID,
            parent: 0,
            name: vault_name.to_string(),
            kind: NodeKind::Dir,
            size: 0,
            offset: 0,
            enc_len: 0,
            nonce: Vec::new(),
            mtime: None,
        };
        Self {
            vault_name: vault_name.to_string(),
            created_at,
            next_id: ROOT_ID + 1,
            nodes: vec![root],
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| VaultError::Integrity)
    }

    /// Parse a decrypted index. The bytes are already authenticated, so a parse
    /// failure here means a genuinely malformed index, not tampering -- but it
    /// is still reported as an integrity failure rather than repaired.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let idx: Self = serde_json::from_slice(bytes).map_err(|_| VaultError::Integrity)?;
        idx.check_structure()?;
        Ok(idx)
    }

    /// Reject an index that could not have been produced by this program:
    /// a missing root, duplicate ids, a parent that does not exist, or a cycle.
    /// Without this a hostile vault could send the tree walk into an infinite
    /// loop after the password check passed.
    fn check_structure(&self) -> Result<()> {
        let mut seen: HashMap<u64, &Node> = HashMap::with_capacity(self.nodes.len());
        for n in &self.nodes {
            if seen.insert(n.id, n).is_some() {
                return Err(VaultError::Integrity);
            }
        }
        let root = seen.get(&ROOT_ID).ok_or(VaultError::Integrity)?;
        if !root.is_dir() {
            return Err(VaultError::Integrity);
        }

        for n in &self.nodes {
            if n.id == ROOT_ID {
                continue;
            }
            let parent = seen.get(&n.parent).ok_or(VaultError::Integrity)?;
            if !parent.is_dir() {
                return Err(VaultError::Integrity);
            }
            // Walk to the root; the node count bounds the depth, so a cycle
            // cannot spin forever.
            let mut cur = n.parent;
            let mut hops = 0usize;
            while cur != ROOT_ID {
                let p = seen.get(&cur).ok_or(VaultError::Integrity)?;
                cur = p.parent;
                hops += 1;
                if hops > self.nodes.len() {
                    return Err(VaultError::Integrity);
                }
            }
        }
        Ok(())
    }

    pub fn get(&self, id: u64) -> Result<&Node> {
        self.nodes.iter().find(|n| n.id == id).ok_or(VaultError::NoSuchEntry)
    }

    fn get_mut(&mut self, id: u64) -> Result<&mut Node> {
        self.nodes.iter_mut().find(|n| n.id == id).ok_or(VaultError::NoSuchEntry)
    }

    /// Direct children of `parent`, folders first then files, each alphabetical.
    pub fn children(&self, parent: u64) -> Vec<&Node> {
        let mut kids: Vec<&Node> = self.nodes.iter().filter(|n| n.parent == parent && n.id != ROOT_ID).collect();
        kids.sort_by(|a, b| {
            b.is_dir()
                .cmp(&a.is_dir())
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        kids
    }

    /// Look up a child by name, ignoring case. Case-insensitive because these
    /// names have to survive a round trip through a Windows filesystem.
    pub fn find_child(&self, parent: u64, name: &str) -> Option<&Node> {
        let lower = name.to_lowercase();
        self.nodes
            .iter()
            .find(|n| n.parent == parent && n.id != ROOT_ID && n.name.to_lowercase() == lower)
    }

    /// Slash-joined path from the root, excluding the root's own name.
    pub fn path_of(&self, id: u64) -> Result<String> {
        let mut parts = Vec::new();
        let mut cur = id;
        let mut hops = 0usize;
        while cur != ROOT_ID {
            let n = self.get(cur)?;
            parts.push(n.name.clone());
            cur = n.parent;
            hops += 1;
            if hops > self.nodes.len() {
                return Err(VaultError::Integrity);
            }
        }
        parts.reverse();
        Ok(parts.join("/"))
    }

    /// Every id in the subtree rooted at `id`, `id` itself last, so callers can
    /// delete children before parents.
    pub fn subtree(&self, id: u64) -> Vec<u64> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        let mut guard = 0usize;
        while let Some(cur) = stack.pop() {
            guard += 1;
            if guard > self.nodes.len() + 1 {
                break;
            }
            for c in self.nodes.iter().filter(|n| n.parent == cur && n.id != ROOT_ID) {
                stack.push(c.id);
            }
            out.push(cur);
        }
        out.reverse();
        out
    }

    pub fn is_descendant_of(&self, candidate: u64, ancestor: u64) -> bool {
        let mut cur = candidate;
        let mut hops = 0usize;
        while cur != ROOT_ID && cur != 0 {
            if cur == ancestor {
                return true;
            }
            match self.get(cur) {
                Ok(n) => cur = n.parent,
                Err(_) => return false,
            }
            hops += 1;
            if hops > self.nodes.len() {
                return false;
            }
        }
        cur == ancestor
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn add_dir(&mut self, parent: u64, name: &str, mtime: Option<i64>) -> Result<u64> {
        let name = validate_name(name)?;
        if !self.get(parent)?.is_dir() {
            return Err(VaultError::InvalidInput("The destination is not a folder.".into()));
        }
        if self.find_child(parent, &name).is_some() {
            return Err(VaultError::AlreadyExists { name });
        }
        let id = self.take_id();
        self.nodes.push(Node {
            id,
            parent,
            name,
            kind: NodeKind::Dir,
            size: 0,
            offset: 0,
            enc_len: 0,
            nonce: Vec::new(),
            mtime,
        });
        Ok(id)
    }

    /// Register a file whose ciphertext has already been written at `offset`.
    #[allow(clippy::too_many_arguments)]
    pub fn add_file(
        &mut self,
        id: u64,
        parent: u64,
        name: &str,
        size: u64,
        offset: u64,
        enc_len: u64,
        nonce: Vec<u8>,
        mtime: Option<i64>,
    ) -> Result<()> {
        let name = validate_name(name)?;
        if self.find_child(parent, &name).is_some() {
            return Err(VaultError::AlreadyExists { name });
        }
        self.nodes.push(Node {
            id,
            parent,
            name,
            kind: NodeKind::File,
            size,
            offset,
            enc_len,
            nonce,
            mtime,
        });
        Ok(())
    }

    /// Reserve an id before the content is written, because the id is bound
    /// into the file's associated data and must be fixed first.
    pub fn reserve_file_id(&mut self) -> u64 {
        self.take_id()
    }

    pub fn rename(&mut self, id: u64, new_name: &str) -> Result<()> {
        if id == ROOT_ID {
            return Err(VaultError::InvalidInput("The vault root cannot be renamed here.".into()));
        }
        let new_name = validate_name(new_name)?;
        let parent = self.get(id)?.parent;
        if let Some(existing) = self.find_child(parent, &new_name) {
            if existing.id != id {
                return Err(VaultError::AlreadyExists { name: new_name });
            }
        }
        self.get_mut(id)?.name = new_name;
        Ok(())
    }

    pub fn move_node(&mut self, id: u64, new_parent: u64) -> Result<()> {
        if id == ROOT_ID {
            return Err(VaultError::InvalidMove);
        }
        if !self.get(new_parent)?.is_dir() {
            return Err(VaultError::InvalidInput("The destination is not a folder.".into()));
        }
        if id == new_parent || self.is_descendant_of(new_parent, id) {
            return Err(VaultError::InvalidMove);
        }
        let name = self.get(id)?.name.clone();
        if let Some(existing) = self.find_child(new_parent, &name) {
            if existing.id != id {
                return Err(VaultError::AlreadyExists { name });
            }
        }
        self.get_mut(id)?.parent = new_parent;
        Ok(())
    }

    /// Remove a subtree. Returns the ciphertext bytes that became dead space.
    pub fn remove_subtree(&mut self, id: u64) -> Result<u64> {
        if id == ROOT_ID {
            return Err(VaultError::InvalidInput("The vault root cannot be deleted.".into()));
        }
        self.get(id)?;
        let ids = self.subtree(id);
        let mut freed = 0u64;
        for n in self.nodes.iter().filter(|n| ids.contains(&n.id)) {
            freed = freed.saturating_add(n.enc_len);
        }
        self.nodes.retain(|n| !ids.contains(&n.id));
        Ok(freed)
    }

    /// (file count, folder count, total plaintext bytes)
    pub fn stats(&self) -> (u64, u64, u64) {
        let mut files = 0;
        let mut dirs = 0;
        let mut bytes = 0;
        for n in &self.nodes {
            if n.id == ROOT_ID {
                continue;
            }
            if n.is_dir() {
                dirs += 1;
            } else {
                files += 1;
                bytes += n.size;
            }
        }
        (files, dirs, bytes)
    }
}

/// Windows device names, which cannot be used as filenames even with an
/// extension. Checked so an export cannot fail halfway through a large restore.
const RESERVED_STEMS: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Validate a single path component.
///
/// This is a security boundary, not a convenience check. The index is
/// authenticated but its *contents* are chosen by whoever created the vault, so
/// a vault shared with you could carry a name like `..\\..\\startup\\evil.exe`.
/// Every name is checked here before it is written into the index and again
/// before it is used to build an export path.
pub fn validate_name(name: &str) -> Result<String> {
    let trimmed = name.trim_end_matches([' ', '.']);
    let bad = |why: &str| Err(VaultError::InvalidInput(format!("Invalid name: {why}.")));

    if name.is_empty() || trimmed.is_empty() {
        return bad("a name cannot be empty");
    }
    // Windows silently strips trailing dots and spaces, so `report.` and
    // `report` become the same file on export. Refuse the name here rather than
    // discover the collision halfway through restoring someone's folder.
    if trimmed.len() != name.len() {
        return bad("a name cannot end with a dot or a space");
    }
    if name.len() > 255 {
        return bad("that name is too long");
    }
    if name == "." || name == ".." {
        return bad("'.' and '..' are not names");
    }
    if name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|']) {
        return bad("these characters are not allowed: / \\ : * ? \" < > |");
    }
    if name.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
        return bad("control characters are not allowed");
    }
    let stem = name.split('.').next().unwrap_or(name).to_lowercase();
    if RESERVED_STEMS.contains(&stem.as_str()) {
        return bad("that is a reserved device name on Windows");
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> VaultIndex {
        let mut idx = VaultIndex::new("MyVault", 0);
        let docs = idx.add_dir(ROOT_ID, "Documents", None).unwrap();
        let photos = idx.add_dir(ROOT_ID, "Photos", None).unwrap();
        let id = idx.reserve_file_id();
        idx.add_file(id, docs, "Resume.pdf", 100, 312, 116, vec![0; 19], None).unwrap();
        let id2 = idx.reserve_file_id();
        idx.add_file(id2, ROOT_ID, "notes.txt", 10, 428, 26, vec![1; 19], None).unwrap();
        let _ = photos;
        idx
    }

    #[test]
    fn json_round_trip_preserves_the_tree() {
        let idx = tree();
        let back = VaultIndex::from_json(&idx.to_json().unwrap()).unwrap();
        assert_eq!(back.nodes.len(), idx.nodes.len());
        assert_eq!(back.stats(), idx.stats());
    }

    #[test]
    fn children_are_folders_first_then_alphabetical() {
        let idx = tree();
        let names: Vec<&str> = idx.children(ROOT_ID).iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["Documents", "Photos", "notes.txt"]);
    }

    #[test]
    fn path_of_joins_with_slashes_and_omits_the_root() {
        let idx = tree();
        let resume = idx.nodes.iter().find(|n| n.name == "Resume.pdf").unwrap();
        assert_eq!(idx.path_of(resume.id).unwrap(), "Documents/Resume.pdf");
        assert_eq!(idx.path_of(ROOT_ID).unwrap(), "");
    }

    #[test]
    fn duplicate_names_are_refused_case_insensitively() {
        let mut idx = tree();
        assert!(idx.add_dir(ROOT_ID, "documents", None).is_err());
    }

    #[test]
    fn unicode_names_are_accepted() {
        let mut idx = VaultIndex::new("v", 0);
        let d = idx.add_dir(ROOT_ID, "Fotos de Verão 📸", None).unwrap();
        let id = idx.reserve_file_id();
        idx.add_file(id, d, "履歴書.pdf", 1, 312, 17, vec![0; 19], None).unwrap();
        let back = VaultIndex::from_json(&idx.to_json().unwrap()).unwrap();
        assert_eq!(back.path_of(id).unwrap(), "Fotos de Verão 📸/履歴書.pdf");
    }

    #[test]
    fn path_traversal_names_are_refused() {
        for evil in ["..", ".", "../etc/passwd", "..\\..\\evil.exe", "a/b", "a\\b", "C:evil"] {
            assert!(validate_name(evil).is_err(), "{evil} should be refused");
        }
    }

    #[test]
    fn windows_device_names_are_refused() {
        for evil in ["CON", "nul", "LPT1", "com9.txt", "AUX.tar.gz"] {
            assert!(validate_name(evil).is_err(), "{evil} should be refused");
        }
    }

    #[test]
    fn control_characters_are_refused() {
        assert!(validate_name("bad\u{0}name").is_err());
        assert!(validate_name("bad\nname").is_err());
    }

    #[test]
    fn trailing_dots_and_spaces_are_refused() {
        assert!(validate_name("report.").is_err());
        assert!(validate_name("report ").is_err());
        assert!(validate_name("...").is_err());
    }

    #[test]
    fn moving_a_folder_into_its_own_child_is_refused() {
        let mut idx = VaultIndex::new("v", 0);
        let a = idx.add_dir(ROOT_ID, "a", None).unwrap();
        let b = idx.add_dir(a, "b", None).unwrap();
        assert!(matches!(idx.move_node(a, b), Err(VaultError::InvalidMove)));
        assert!(matches!(idx.move_node(a, a), Err(VaultError::InvalidMove)));
        assert!(idx.move_node(b, ROOT_ID).is_ok());
    }

    #[test]
    fn deleting_a_folder_removes_the_whole_subtree_and_reports_dead_bytes() {
        let mut idx = tree();
        let docs = idx.find_child(ROOT_ID, "Documents").unwrap().id;
        let freed = idx.remove_subtree(docs).unwrap();
        assert_eq!(freed, 116);
        assert!(idx.find_child(ROOT_ID, "Documents").is_none());
        assert_eq!(idx.stats().0, 1, "only notes.txt should remain");
    }

    #[test]
    fn the_root_cannot_be_deleted_or_moved() {
        let mut idx = tree();
        assert!(idx.remove_subtree(ROOT_ID).is_err());
        assert!(idx.move_node(ROOT_ID, ROOT_ID).is_err());
    }

    #[test]
    fn an_index_with_a_cycle_is_refused_rather_than_looped_over() {
        let mut idx = VaultIndex::new("v", 0);
        let a = idx.add_dir(ROOT_ID, "a", None).unwrap();
        let b = idx.add_dir(a, "b", None).unwrap();
        // Forge a cycle: a's parent becomes its own descendant.
        idx.nodes.iter_mut().find(|n| n.id == a).unwrap().parent = b;
        let json = serde_json::to_vec(&idx).unwrap();
        assert!(matches!(VaultIndex::from_json(&json), Err(VaultError::Integrity)));
    }

    #[test]
    fn an_index_with_a_dangling_parent_is_refused() {
        let mut idx = VaultIndex::new("v", 0);
        let a = idx.add_dir(ROOT_ID, "a", None).unwrap();
        idx.nodes.iter_mut().find(|n| n.id == a).unwrap().parent = 9999;
        let json = serde_json::to_vec(&idx).unwrap();
        assert!(matches!(VaultIndex::from_json(&json), Err(VaultError::Integrity)));
    }

    #[test]
    fn an_index_with_duplicate_ids_is_refused() {
        let mut idx = VaultIndex::new("v", 0);
        idx.add_dir(ROOT_ID, "a", None).unwrap();
        let mut dup = idx.nodes[1].clone();
        dup.name = "b".into();
        idx.nodes.push(dup);
        let json = serde_json::to_vec(&idx).unwrap();
        assert!(matches!(VaultIndex::from_json(&json), Err(VaultError::Integrity)));
    }

    #[test]
    fn an_index_without_a_root_is_refused() {
        let mut idx = VaultIndex::new("v", 0);
        idx.nodes.clear();
        let json = serde_json::to_vec(&idx).unwrap();
        assert!(matches!(VaultIndex::from_json(&json), Err(VaultError::Integrity)));
    }

    #[test]
    fn garbage_json_is_refused() {
        assert!(VaultIndex::from_json(b"not json at all").is_err());
        assert!(VaultIndex::from_json(b"").is_err());
    }
}
