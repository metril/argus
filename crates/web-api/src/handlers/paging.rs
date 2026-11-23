//! Keyset (cursor) pagination over an in-memory, sorted result.
//!
//! Every row gets a sort key (a string whose byte order is the display order) and its id as a
//! tie-breaker. A cursor is the key and id of the last row served, so the next page starts
//! after that position even if rows were inserted or deleted in between (an offset would skip
//! or repeat rows).

use base64::Engine;

use crate::error::{ApiError, ApiResult};

pub const DEFAULT_LIMIT: u32 = 40;
pub const MAX_LIMIT: u32 = 200;

/// A row with its sort position.
pub struct Keyed<T> {
    pub key: String,
    pub id: String,
    /// The display name, for the A-Z rail.
    pub label: String,
    pub item: T,
}

pub struct CursorPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub total: usize,
    pub limit: u32,
    pub has_more: bool,
    /// Echoed when the deprecated `page` parameter was used.
    pub page: Option<u32>,
    /// First characters present among all matching rows (`A`-`Z`, `#` for the rest).
    pub letters: Vec<String>,
}

/// The A-Z rail letter of `name`.
fn letter(name: &str) -> char {
    name.chars()
        .find(|c| !c.is_whitespace())
        .map(|c| c.to_uppercase().next().unwrap_or(c))
        .filter(char::is_ascii_alphabetic)
        .unwrap_or('#')
}

/// Sort key for natural order: case-insensitive, digit runs compare by value
/// (`shop-2` < `shop-10`).
pub fn natural_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    let mut digits = String::new();
    let flush = |digits: &mut String, out: &mut String| {
        if !digits.is_empty() {
            let t = digits.trim_start_matches('0');
            // Length first (fixed width), so shorter numbers sort before longer ones.
            let t = if t.is_empty() { "0" } else { t };
            out.push_str(&format!("{:03}", t.len().min(999)));
            out.push_str(t);
            digits.clear();
        }
    };
    for c in s.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            flush(&mut digits, &mut out);
            out.extend(c.to_lowercase());
        }
    }
    flush(&mut digits, &mut out);
    out
}

/// Key part that sorts larger numbers first.
pub fn desc_key(n: u64) -> String {
    format!("{:020}", u64::MAX - n)
}

fn encode(key: &str, id: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{key}\0{id}"))
}

fn decode(token: &str) -> ApiResult<(String, String)> {
    let bad = || ApiError::ValidationError("invalid cursor".into());
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| bad())?;
    let s = String::from_utf8(raw).map_err(|_| bad())?;
    let (k, i) = s.split_once('\0').ok_or_else(bad)?;
    Ok((k.to_string(), i.to_string()))
}

/// Serve one page of `rows`.
///
/// * `cursor`: start after that position (wins over `from` and `page`).
/// * `from`: start at the first row whose key is >= `from_key` (a name-sorted seek).
/// * `page`: deprecated 1-based offset paging.
pub fn paginate<T>(
    mut rows: Vec<Keyed<T>>,
    limit: Option<u32>,
    cursor: Option<&str>,
    from_key: Option<&str>,
    page: Option<u32>,
) -> ApiResult<CursorPage<T>> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    rows.sort_by(|a, b| (&a.key, &a.id).cmp(&(&b.key, &b.id)));
    let total = rows.len();
    let letters: Vec<String> = rows
        .iter()
        .map(|r| letter(&r.label))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(String::from)
        .collect();
    let (start, page_echo) = if let Some(c) = cursor.filter(|c| !c.is_empty()) {
        let (k, i) = decode(c)?;
        (
            rows.partition_point(|r| (r.key.as_str(), r.id.as_str()) <= (k.as_str(), i.as_str())),
            None,
        )
    } else if let Some(f) = from_key {
        (rows.partition_point(|r| r.key.as_str() < f), None)
    } else if let Some(p) = page {
        let p = p.max(1);
        (((p - 1) as usize).saturating_mul(limit as usize), Some(p))
    } else {
        (0, None)
    };
    let end = start.saturating_add(limit as usize).min(total);
    let start = start.min(total);
    let has_more = end < total;
    let next_cursor = (has_more && end > start).then(|| {
        let last = &rows[end - 1];
        encode(&last.key, &last.id)
    });
    let items = rows.drain(start..end).map(|r| r.item).collect();
    Ok(CursorPage {
        items,
        next_cursor,
        total,
        limit,
        has_more,
        page: page_echo,
        letters,
    })
}

/// Sort key for a timestamp, oldest first (RFC 3339 text; unparsable sorts first).
pub fn ts_key(rfc3339: &str) -> String {
    format!("{:020}", ts_millis(rfc3339))
}

/// Sort key for a timestamp, newest first.
pub fn ts_key_desc(rfc3339: &str) -> String {
    desc_key(ts_millis(rfc3339))
}

fn ts_millis(rfc3339: &str) -> u64 {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| t.timestamp_millis().max(0) as u64)
        .unwrap_or(0)
}

/// Serve a [`api_types::Page`] (default page size 50) from keyed rows, honouring `cursor` and
/// the deprecated `page`.
pub fn page_of<T>(rows: Vec<Keyed<T>>, q: &super::CursorQuery) -> ApiResult<api_types::Page<T>> {
    let p = paginate(
        rows,
        Some(q.limit.unwrap_or(50)),
        q.cursor.as_deref(),
        None,
        q.page,
    )?;
    Ok(api_types::Page {
        items: p.items,
        total: p.total,
        page: p.page.unwrap_or(1),
        limit: p.limit,
        has_more: p.has_more,
        next_cursor: p.next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(names: &[&str]) -> Vec<Keyed<String>> {
        names
            .iter()
            .map(|n| Keyed {
                key: natural_key(n),
                id: n.to_string(),
                label: n.to_string(),
                item: n.to_string(),
            })
            .collect()
    }

    #[test]
    fn natural_order() {
        let mut v = ["shop-10", "Shop-2", "shop-1", "shop-100", "a", "shop-02"];
        v.sort_by_key(|s| natural_key(s));
        assert_eq!(
            v,
            ["a", "shop-1", "Shop-2", "shop-02", "shop-10", "shop-100"]
        );
        let mut big = ["x9999999999", "x12345678901", "x100000000000", "x2"];
        big.sort_by_key(|s| natural_key(s));
        assert_eq!(big, ["x2", "x9999999999", "x12345678901", "x100000000000"]);
    }

    #[test]
    fn cursor_survives_inserts_and_deletes_between_pages() {
        let names: Vec<String> = (1..=10).map(|i| format!("n-{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let p1 = paginate(rows(&refs), Some(3), None, None, None).unwrap();
        assert_eq!(p1.items, ["n-1", "n-2", "n-3"]);
        // A row before the cursor is inserted and the cursor's own row is deleted.
        let mut changed: Vec<&str> = refs.iter().copied().filter(|n| *n != "n-3").collect();
        changed.push("n-0");
        let p2 = paginate(
            rows(&changed),
            Some(3),
            p1.next_cursor.as_deref(),
            None,
            None,
        )
        .unwrap();
        assert_eq!(p2.items, ["n-4", "n-5", "n-6"], "no repeat, no skip");
        assert!(paginate(rows(&refs), None, Some("!!"), None, None).is_err());
    }

    #[test]
    fn letters_cover_every_matching_row_not_just_the_page() {
        let p = paginate(
            rows(&["apple", "Bob", "9lives", "cat", "avocado"]),
            Some(1),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(p.letters, ["#", "A", "B", "C"]);
    }

    #[test]
    fn last_page_has_no_cursor_and_from_seeks() {
        let p = paginate(rows(&["a", "b", "c"]), Some(5), None, None, None).unwrap();
        assert!(p.next_cursor.is_none() && !p.has_more);
        let p = paginate(
            rows(&["apple", "bob", "cat"]),
            Some(5),
            None,
            Some("b"),
            None,
        )
        .unwrap();
        assert_eq!(p.items, ["bob", "cat"]);
        let p = paginate(rows(&["a", "b", "c", "d"]), Some(2), None, None, Some(2)).unwrap();
        assert_eq!(
            (p.items, p.page),
            (vec!["c".to_string(), "d".to_string()], Some(2))
        );
    }
}
