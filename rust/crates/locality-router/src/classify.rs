// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A small SQL classifier: finds the first table of a statement, an equality
//! on a column that may be the integer primary key, and whether the statement
//! can change session state. It never rejects SQL; anything it does not
//! understand is `Other` and keeps the current backend.

/// Statement kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `BEGIN` / `START TRANSACTION`.
    Begin,
    /// `COMMIT`.
    Commit,
    /// `ROLLBACK` (without `TO SAVEPOINT`).
    Rollback,
    /// `SELECT` / `WITH`.
    Select,
    /// `INSERT` / `REPLACE`.
    Insert,
    /// `UPDATE`.
    Update,
    /// `DELETE`.
    Delete,
    /// `USE db`.
    Use,
    /// Anything else.
    Other,
}

/// Where the value of a point equality comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An integer literal in the SQL text.
    Literal(i64),
    /// The n-th `?` placeholder (0-based).
    Param(usize),
}

/// A `column = value` equality that may select one row by primary key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point {
    /// Lower-cased column name.
    pub column: String,
    /// Value source.
    pub value: Value,
}

/// Classification of one statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    /// Statement kind.
    pub kind: Kind,
    /// First table as (database, table), lower-cased.
    pub table: Option<(Option<String>, String)>,
    /// Point equality on the first table, if any.
    pub point: Option<Point>,
    /// Whether executing the statement may change session state that a
    /// session migration must carry (variables, prepared statements, ...).
    pub dirty: bool,
    /// For `USE db`: the database.
    pub use_db: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),   // bare identifier or keyword, lower-cased
    Quoted(String), // `quoted` identifier
    Int(i64),
    Str,
    Param,
    Punct(u8),
    Var, // @name or @@name
}

fn tokenize(sql: &[u8], limit: usize) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < sql.len() && out.len() < limit {
        let c = sql[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c == b'#' || (c == b'-' && sql.get(i + 1) == Some(&b'-')) {
            while i < sql.len() && sql[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && sql.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < sql.len() && !(sql[i] == b'*' && sql[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else if c == b'`' {
            let start = i + 1;
            i = start;
            while i < sql.len() && sql[i] != b'`' {
                i += 1;
            }
            out.push(Tok::Quoted(String::from_utf8_lossy(&sql[start..i.min(sql.len())]).to_lowercase()));
            i += 1;
        } else if c == b'\'' || c == b'"' {
            i += 1;
            while i < sql.len() {
                if sql[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if sql[i] == c {
                    if sql.get(i + 1) == Some(&c) {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            i += 1;
            out.push(Tok::Str);
        } else if c.is_ascii_digit() {
            let start = i;
            while i < sql.len() && (sql[i].is_ascii_alphanumeric() || sql[i] == b'.') {
                i += 1;
            }
            let text = std::str::from_utf8(&sql[start..i]).unwrap_or("");
            match text.parse::<i64>() {
                Ok(v) => out.push(Tok::Int(v)),
                Err(_) => out.push(Tok::Str),
            }
        } else if c.is_ascii_alphabetic() || c == b'_' || c >= 0x80 || c == b'$' {
            let start = i;
            while i < sql.len() && (sql[i].is_ascii_alphanumeric() || sql[i] == b'_' || sql[i] >= 0x80 || sql[i] == b'$') {
                i += 1;
            }
            out.push(Tok::Word(String::from_utf8_lossy(&sql[start..i]).to_lowercase()));
        } else if c == b'?' {
            out.push(Tok::Param);
            i += 1;
        } else if c == b'@' {
            while i < sql.len() && (sql[i] == b'@' || sql[i].is_ascii_alphanumeric() || sql[i] == b'_' || sql[i] == b'.') {
                i += 1;
            }
            out.push(Tok::Var);
        } else {
            out.push(Tok::Punct(c));
            i += 1;
        }
    }
    out
}

fn word(t: Option<&Tok>) -> Option<&str> {
    match t {
        Some(Tok::Word(w)) => Some(w),
        _ => None,
    }
}

fn ident(t: Option<&Tok>) -> Option<&str> {
    match t {
        Some(Tok::Word(w) | Tok::Quoted(w)) => Some(w),
        _ => None,
    }
}

/// Reads `[db.]table` at `*i`.
fn table_ref(toks: &[Tok], i: &mut usize) -> Option<(Option<String>, String)> {
    let first = ident(toks.get(*i))?;
    if matches!(toks.get(*i), Some(Tok::Word(w)) if is_reserved(w)) {
        return None;
    }
    let first = first.to_owned();
    *i += 1;
    if toks.get(*i) == Some(&Tok::Punct(b'.')) {
        let second = ident(toks.get(*i + 1))?.to_owned();
        *i += 2;
        return Some((Some(first), second));
    }
    Some((None, first))
}

fn is_reserved(w: &str) -> bool {
    matches!(w, "select" | "where" | "set" | "values" | "value" | "(" | "dual" | "lateral")
}

/// Finds the first `col = value` after `WHERE`, counting placeholders.
fn where_point(toks: &[Tok], from: usize) -> Option<Point> {
    let mut params_before = toks[..from].iter().filter(|t| **t == Tok::Param).count();
    let mut i = from;
    while i < toks.len() && word(toks.get(i)) != Some("where") {
        if toks[i] == Tok::Param {
            params_before += 1;
        }
        i += 1;
    }
    while i + 2 < toks.len() {
        if toks[i] == Tok::Param {
            params_before += 1;
        }
        if let (Some(col), Tok::Punct(b'='), v) = (ident(toks.get(i)), &toks[i + 1], &toks[i + 2]) {
            // Skip qualified `t.col` prefixes by taking the last identifier.
            let value = match v {
                Tok::Int(n) => Some(Value::Literal(*n)),
                Tok::Param => Some(Value::Param(params_before)),
                _ => None,
            };
            if let Some(value) = value {
                return Some(Point { column: col.to_owned(), value });
            }
        }
        i += 1;
    }
    None
}

/// `INSERT INTO t (c1, c2, ...) VALUES (v1, v2, ...)`: value of `column`.
fn insert_points(toks: &[Tok], after_table: usize) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    if toks.get(after_table) != Some(&Tok::Punct(b'(')) {
        return out;
    }
    let mut cols = Vec::new();
    let mut i = after_table + 1;
    while let Some(t) = toks.get(i) {
        match t {
            Tok::Punct(b')') => break,
            Tok::Punct(b',') => {}
            _ => cols.push(ident(Some(t)).unwrap_or("").to_owned()),
        }
        i += 1;
    }
    i += 1;
    if !matches!(word(toks.get(i)), Some("values" | "value")) || toks.get(i + 1) != Some(&Tok::Punct(b'(')) {
        return out;
    }
    let mut params = toks[..i].iter().filter(|t| **t == Tok::Param).count();
    i += 2;
    let mut col = 0;
    let mut depth = 0;
    let mut simple = true;
    let mut value = None;
    while let Some(t) = toks.get(i) {
        match t {
            Tok::Punct(b'(') => {
                depth += 1;
                simple = false;
            }
            Tok::Punct(b')') if depth == 0 => {
                if simple && let (Some(v), Some(c)) = (value.take(), cols.get(col)) {
                    out.push((c.clone(), v));
                }
                break;
            }
            Tok::Punct(b')') => depth -= 1,
            Tok::Punct(b',') if depth == 0 => {
                if simple && let (Some(v), Some(c)) = (value.take(), cols.get(col)) {
                    out.push((c.clone(), v));
                }
                col += 1;
                simple = true;
                value = None;
            }
            Tok::Param => {
                if value.is_none() && simple {
                    value = Some(Value::Param(params));
                } else {
                    simple = false;
                }
                params += 1;
            }
            Tok::Int(n) => {
                if value.is_none() && simple {
                    value = Some(Value::Literal(*n));
                } else {
                    simple = false;
                }
            }
            _ => simple = false,
        }
        i += 1;
    }
    out
}

/// Classifies one SQL statement.
pub fn classify(sql: &[u8]) -> Classified {
    let toks = tokenize(sql, 4096);
    let has_var = toks.contains(&Tok::Var);
    let mentions = |names: &[&str]| toks.iter().any(|t| matches!(t, Tok::Word(w) if names.contains(&w.as_str())));
    let session_fn = mentions(&["last_insert_id", "found_rows", "row_count", "get_lock", "release_lock"]);
    let mut c = Classified { kind: Kind::Other, table: None, point: None, dirty: true, use_db: None };
    let Some(first) = word(toks.first()) else {
        return c;
    };
    match first {
        "begin" if toks.len() == 1 || matches!(word(toks.get(1)), Some("pessimistic" | "optimistic" | "work")) => {
            c.kind = Kind::Begin;
        }
        "start" if word(toks.get(1)) == Some("transaction") => c.kind = Kind::Begin,
        "commit" => c.kind = Kind::Commit,
        "rollback" if !mentions(&["savepoint"]) && word(toks.get(1)) != Some("to") => c.kind = Kind::Rollback,
        "use" => {
            c.kind = Kind::Use;
            c.use_db = ident(toks.get(1)).map(str::to_owned);
            return c;
        }
        "select" | "with" | "(" => {
            c.kind = Kind::Select;
            if mentions(&["into"]) {
                return c;
            }
            if let Some(pos) = toks.iter().position(|t| word(Some(t)) == Some("from")) {
                let mut i = pos + 1;
                c.table = table_ref(&toks, &mut i);
                if c.table.is_some() {
                    c.point = where_point(&toks, i);
                }
            }
        }
        "update" => {
            c.kind = Kind::Update;
            let mut i = 1;
            while matches!(word(toks.get(i)), Some("low_priority" | "ignore")) {
                i += 1;
            }
            c.table = table_ref(&toks, &mut i);
            if c.table.is_some() {
                c.point = where_point(&toks, i);
            }
        }
        "delete" => {
            c.kind = Kind::Delete;
            if let Some(pos) = toks.iter().position(|t| word(Some(t)) == Some("from")) {
                let mut i = pos + 1;
                c.table = table_ref(&toks, &mut i);
                if c.table.is_some() {
                    c.point = where_point(&toks, i);
                }
            }
        }
        "insert" | "replace" => {
            c.kind = Kind::Insert;
            let mut i = 1;
            while matches!(word(toks.get(i)), Some("low_priority" | "delayed" | "high_priority" | "ignore" | "into")) {
                i += 1;
            }
            c.table = table_ref(&toks, &mut i);
            if c.table.is_some() {
                // Every candidate column is kept; the router picks the one
                // that is the table's integer handle.
                if let Some((col, value)) = insert_points(&toks, i).into_iter().next() {
                    c.point = Some(Point { column: col, value });
                }
                c.point = insert_points(&toks, i)
                    .into_iter()
                    .find(|(col, _)| col == "id")
                    .map(|(column, value)| Point { column, value })
                    .or(c.point);
            }
        }
        _ => return c,
    }
    c.dirty = has_var || session_fn;
    c
}

/// All `column = value` candidates of an INSERT, for the router to match
/// against the real primary key name.
pub fn insert_candidates(sql: &[u8]) -> Vec<(String, Value)> {
    let toks = tokenize(sql, 4096);
    let mut i = 1;
    while matches!(word(toks.get(i)), Some("low_priority" | "delayed" | "high_priority" | "ignore" | "into")) {
        i += 1;
    }
    if table_ref(&toks, &mut i).is_none() {
        return Vec::new();
    }
    insert_points(&toks, i)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(db: Option<&str>, name: &str) -> Option<(Option<String>, String)> {
        Some((db.map(str::to_owned), name.to_owned()))
    }

    #[test]
    fn sysbench_statements() {
        let c = classify(b"SELECT c FROM sbtest7 WHERE id=?");
        assert_eq!(c.kind, Kind::Select);
        assert_eq!(c.table, t(None, "sbtest7"));
        assert_eq!(c.point, Some(Point { column: "id".into(), value: Value::Param(0) }));
        assert!(!c.dirty);

        let c = classify(b"UPDATE sbtest3 SET k=k+1 WHERE id=?");
        assert_eq!(c.table, t(None, "sbtest3"));
        assert_eq!(c.point, Some(Point { column: "id".into(), value: Value::Param(0) }));

        let c = classify(b"UPDATE sbtest3 SET c=? WHERE id=?");
        assert_eq!(c.point, Some(Point { column: "id".into(), value: Value::Param(1) }));

        let c = classify(b"DELETE FROM `test`.`sbtest2` WHERE id = 42");
        assert_eq!(c.table, t(Some("test"), "sbtest2"));
        assert_eq!(c.point, Some(Point { column: "id".into(), value: Value::Literal(42) }));

        let c = classify(b"INSERT INTO sbtest9 (id, k, c, pad) VALUES (?, ?, ?, ?)");
        assert_eq!(c.kind, Kind::Insert);
        assert_eq!(c.table, t(None, "sbtest9"));
        assert_eq!(c.point, Some(Point { column: "id".into(), value: Value::Param(0) }));

        let c = classify(b"SELECT id, k, c, pad FROM sbtest1 WHERE k IN (?, ?, ?)");
        assert_eq!(c.table, t(None, "sbtest1"));
        assert_eq!(c.point, None);

        let c = classify(b"SELECT c FROM sbtest1 WHERE id BETWEEN ? AND ? ORDER BY c");
        assert_eq!(c.point, None);
    }

    #[test]
    fn transactions_and_state() {
        assert_eq!(classify(b"BEGIN").kind, Kind::Begin);
        assert_eq!(classify(b"begin pessimistic").kind, Kind::Begin);
        assert_eq!(classify(b"START TRANSACTION READ ONLY").kind, Kind::Begin);
        assert_eq!(classify(b"COMMIT").kind, Kind::Commit);
        assert_eq!(classify(b"ROLLBACK").kind, Kind::Rollback);
        assert_eq!(classify(b"ROLLBACK TO SAVEPOINT a").kind, Kind::Other);
        assert!(classify(b"SET @a = 1").dirty);
        assert!(classify(b"SELECT @a := c FROM t WHERE id = 1").dirty);
        assert!(classify(b"SELECT LAST_INSERT_ID()").dirty);
        let u = classify(b"use `test_ta`");
        assert_eq!(u.kind, Kind::Use);
        assert_eq!(u.use_db.as_deref(), Some("test_ta"));
        assert!(!classify(b"/* hint */ select 1 from t where id = 1").dirty);
    }
}
