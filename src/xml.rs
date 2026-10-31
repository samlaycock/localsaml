//! A small XML DOM: enough to build SAML messages, parse incoming ones and canonicalize elements
//! with Exclusive XML Canonicalization 1.0 (`xml-exc-c14n#`) for XML signatures.
//!
//! Elements keep the prefixes and namespace declarations they were written (or parsed) with, plus
//! the namespace URI each name resolves to, so the same tree can be serialized for the wire,
//! canonicalized for signing and queried by namespace.

use std::collections::{BTreeMap, BTreeSet};

use quick_xml::events::Event;
use quick_xml::reader::Reader;

pub const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";

/// Deepest element nesting [`parse`] accepts. SAML messages are a dozen levels deep; the limit
/// keeps hostile input from overflowing the stack in the recursive code that walks the tree.
pub const MAX_DEPTH: usize = 128;

/// Namespaces in scope: prefix (`None` for the default namespace) to URI.
pub type Scope = BTreeMap<Option<String>, String>;

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Element(Element),
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Attr {
    pub prefix: Option<String>,
    pub local: String,
    /// The namespace the prefix resolves to; unprefixed attributes have none.
    pub ns: Option<String>,
    pub value: String,
}

impl Attr {
    fn qname(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{}", self.local),
            None => self.local.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Element {
    pub prefix: Option<String>,
    pub local: String,
    pub ns: Option<String>,
    /// Namespace declarations written on this element.
    pub decls: Vec<(Option<String>, String)>,
    pub attrs: Vec<Attr>,
    pub children: Vec<Node>,
}

impl Element {
    /// An element in namespace `ns`, written with `prefix` (empty for the default namespace).
    /// Call [`Element::declare_namespaces`] on the finished tree to add the declarations it needs.
    pub fn new(ns: &str, prefix: &str, local: &str) -> Self {
        Self {
            prefix: (!prefix.is_empty()).then(|| prefix.to_string()),
            local: local.into(),
            ns: (!ns.is_empty()).then(|| ns.to_string()),
            decls: vec![],
            attrs: vec![],
            children: vec![],
        }
    }

    pub fn qname(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{}", self.local),
            None => self.local.clone(),
        }
    }

    pub fn is(&self, ns: &str, local: &str) -> bool {
        self.local == local && self.ns.as_deref() == Some(ns)
    }

    /// Set an unprefixed attribute (replacing any existing one).
    pub fn attr(mut self, name: &str, value: impl Into<String>) -> Self {
        self.set_attr(name, value);
        self
    }

    pub fn attr_opt(self, name: &str, value: Option<impl Into<String>>) -> Self {
        match value {
            Some(v) => self.attr(name, v),
            None => self,
        }
    }

    pub fn set_attr(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        match self.attrs.iter_mut().find(|a| a.prefix.is_none() && a.local == name) {
            Some(a) => a.value = value,
            None => self.attrs.push(Attr { prefix: None, local: name.into(), ns: None, value }),
        }
    }

    /// Set a namespaced attribute such as `xsi:type`.
    pub fn ns_attr(mut self, ns: &str, prefix: &str, local: &str, value: impl Into<String>) -> Self {
        self.attrs.push(Attr {
            prefix: Some(prefix.into()),
            local: local.into(),
            ns: Some(ns.into()),
            value: value.into(),
        });
        self
    }

    /// Declare a namespace on this element up front (e.g. so children share one declaration).
    pub fn declare(mut self, prefix: &str, ns: &str) -> Self {
        let p = (!prefix.is_empty()).then(|| prefix.to_string());
        if !self.decls.iter().any(|(q, _)| *q == p) {
            self.decls.push((p, ns.into()));
        }
        self
    }

    pub fn child(mut self, el: Element) -> Self {
        self.children.push(Node::Element(el));
        self
    }

    pub fn child_opt(self, el: Option<Element>) -> Self {
        match el {
            Some(el) => self.child(el),
            None => self,
        }
    }

    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.children.push(Node::Text(text.into()));
        self
    }

    pub fn get_attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|a| a.prefix.is_none() && a.local == name).map(|a| a.value.as_str())
    }

    pub fn get_ns_attr(&self, ns: &str, local: &str) -> Option<&str> {
        self.attrs.iter().find(|a| a.ns.as_deref() == Some(ns) && a.local == local).map(|a| a.value.as_str())
    }

    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }

    pub fn elements_mut(&mut self) -> impl Iterator<Item = &mut Element> {
        self.children.iter_mut().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }

    /// The first child element named `ns`:`local`.
    pub fn find(&self, ns: &str, local: &str) -> Option<&Element> {
        self.elements().find(|e| e.is(ns, local))
    }

    pub fn find_mut(&mut self, ns: &str, local: &str) -> Option<&mut Element> {
        self.elements_mut().find(|e| e.is(ns, local))
    }

    pub fn find_all<'a>(&'a self, ns: &'a str, local: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.elements().filter(move |e| e.is(ns, local))
    }

    /// Follow a path of child elements, all in namespace `ns`.
    pub fn path(&self, steps: &[(&str, &str)]) -> Option<&Element> {
        steps.iter().try_fold(self, |el, (ns, local)| el.find(ns, local))
    }

    /// All text content, concatenated.
    pub fn text_content(&self) -> String {
        let mut out = String::new();
        fn walk(el: &Element, out: &mut String) {
            for node in &el.children {
                match node {
                    Node::Text(t) => out.push_str(t),
                    Node::Element(e) => walk(e, out),
                }
            }
        }
        walk(self, &mut out);
        out
    }

    /// Trimmed text content.
    pub fn value(&self) -> String {
        self.text_content().trim().to_string()
    }

    /// The element (this one or a descendant) whose `ID` attribute is `id`.
    pub fn find_by_id(&self, id: &str) -> Option<&Element> {
        if self.get_attr("ID") == Some(id) {
            return Some(self);
        }
        self.elements().find_map(|e| e.find_by_id(id))
    }

    pub fn find_by_id_mut(&mut self, id: &str) -> Option<&mut Element> {
        if self.get_attr("ID") == Some(id) {
            return Some(self);
        }
        self.elements_mut().find_map(|e| e.find_by_id_mut(id))
    }

    /// How many elements (this one and its descendants) have `ID` `id`.
    pub fn count_id(&self, id: &str) -> usize {
        usize::from(self.get_attr("ID") == Some(id)) + self.elements().map(|e| e.count_id(id)).sum::<usize>()
    }

    /// Like [`Element::find_by_id`], plus the namespaces in scope from the element's ancestors.
    pub fn find_by_id_scoped(&self, id: &str) -> Option<(&Element, Scope)> {
        fn walk<'a>(el: &'a Element, id: &str, scope: &Scope) -> Option<(&'a Element, Scope)> {
            if el.get_attr("ID") == Some(id) {
                return Some((el, scope.clone()));
            }
            let inner = el.scope_within(scope);
            el.elements().find_map(|e| walk(e, id, &inner))
        }
        walk(self, id, &Scope::new())
    }

    /// The namespaces in scope inside this element, given those in scope outside it.
    pub fn scope_within(&self, outer: &Scope) -> Scope {
        let mut scope = outer.clone();
        for (p, uri) in &self.decls {
            scope.insert(p.clone(), uri.clone());
        }
        scope
    }

    /// Add the namespace declarations this tree needs, on the outermost element that needs each,
    /// assuming `outer` is in scope around it.
    pub fn declare_namespaces_in(&mut self, outer: &Scope) {
        let mut scope = self.scope_within(outer);
        let mut needed: Vec<(Option<String>, String)> =
            vec![(self.prefix.clone(), self.ns.clone().unwrap_or_default())];
        for a in &self.attrs {
            if let (Some(p), Some(ns)) = (&a.prefix, &a.ns)
                && p != "xml"
            {
                needed.push((Some(p.clone()), ns.clone()));
            }
        }
        for (p, ns) in needed {
            let current = scope.get(&p).cloned().unwrap_or_default();
            if current != ns {
                self.decls.push((p.clone(), ns.clone()));
                scope.insert(p, ns);
            }
        }
        for child in self.elements_mut() {
            child.declare_namespaces_in(&scope);
        }
    }

    pub fn declare_namespaces(&mut self) {
        self.declare_namespaces_in(&Scope::new());
    }

    /// Serialize compactly (no added whitespace), for the wire.
    pub fn to_xml(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    /// Serialize with an XML declaration.
    pub fn to_document(&self) -> String {
        format!(r#"<?xml version="1.0" encoding="UTF-8"?>{}"#, self.to_xml())
    }

    fn write_start(&self, out: &mut String) {
        out.push('<');
        out.push_str(&self.qname());
        for (p, uri) in &self.decls {
            match p {
                Some(p) => out.push_str(&format!(r#" xmlns:{p}="{}""#, escape_attr(uri))),
                None => out.push_str(&format!(r#" xmlns="{}""#, escape_attr(uri))),
            }
        }
        for a in &self.attrs {
            out.push_str(&format!(r#" {}="{}""#, a.qname(), escape_attr(&a.value)));
        }
    }

    fn write(&self, out: &mut String) {
        self.write_start(out);
        if self.children.is_empty() {
            out.push_str("/>");
            return;
        }
        out.push('>');
        for node in &self.children {
            match node {
                Node::Text(t) => out.push_str(&escape_text(t)),
                Node::Element(e) => e.write(out),
            }
        }
        out.push_str(&format!("</{}>", self.qname()));
    }

    /// Serialize indented, for people to read. Never sign or send this form: the added
    /// whitespace changes the document.
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out
    }

    fn write_pretty(&self, out: &mut String, depth: usize) {
        let indent = "  ".repeat(depth);
        out.push_str(&indent);
        self.write_start(out);
        let only_text = self.children.iter().all(|n| matches!(n, Node::Text(_)));
        if self.children.is_empty() {
            out.push_str("/>\n");
        } else if only_text {
            out.push('>');
            out.push_str(&escape_text(&self.text_content()));
            out.push_str(&format!("</{}>\n", self.qname()));
        } else {
            out.push_str(">\n");
            for node in &self.children {
                match node {
                    Node::Element(e) => e.write_pretty(out, depth + 1),
                    Node::Text(t) if !t.trim().is_empty() => {
                        out.push_str(&format!("{indent}  {}\n", escape_text(t.trim())));
                    }
                    Node::Text(_) => {}
                }
            }
            out.push_str(&format!("{indent}</{}>\n", self.qname()));
        }
    }

    /// Exclusive XML Canonicalization 1.0 (without comments) of this element, given the
    /// namespaces in scope from its ancestors and an InclusiveNamespaces PrefixList.
    pub fn exc_c14n(&self, outer: &Scope, inclusive: &[String]) -> String {
        let mut out = String::new();
        self.write_c14n(outer, &Scope::new(), inclusive, &mut out);
        out
    }

    fn write_c14n(&self, outer: &Scope, rendered: &Scope, inclusive: &[String], out: &mut String) {
        let scope = self.scope_within(outer);
        // Namespaces visibly utilized by the element or its attributes, plus inclusive prefixes in scope.
        let mut prefixes: BTreeSet<Option<String>> = BTreeSet::new();
        prefixes.insert(self.prefix.clone());
        for a in &self.attrs {
            if let Some(p) = &a.prefix
                && p != "xml"
            {
                prefixes.insert(Some(p.clone()));
            }
        }
        for p in inclusive {
            let key = if p == "#default" { None } else { Some(p.clone()) };
            if scope.contains_key(&key) {
                prefixes.insert(key);
            }
        }
        let mut rendered_here = rendered.clone();
        // BTreeSet order puts the default namespace first, then prefixes in order (C14N §2.2).
        let mut ns_out = String::new();
        for p in prefixes {
            let uri = scope.get(&p).cloned().unwrap_or_default();
            let previous = rendered.get(&p).cloned().unwrap_or_default();
            if uri == previous || (p.is_some() && uri.is_empty()) {
                continue;
            }
            match &p {
                Some(name) => ns_out.push_str(&format!(r#" xmlns:{name}="{}""#, c14n_attr(&uri))),
                None => ns_out.push_str(&format!(r#" xmlns="{}""#, c14n_attr(&uri))),
            }
            rendered_here.insert(p, uri);
        }
        let mut attrs: Vec<&Attr> = self.attrs.iter().collect();
        attrs.sort_by(|a, b| {
            (a.ns.as_deref().unwrap_or(""), a.local.as_str()).cmp(&(b.ns.as_deref().unwrap_or(""), b.local.as_str()))
        });
        out.push('<');
        out.push_str(&self.qname());
        out.push_str(&ns_out);
        for a in attrs {
            out.push_str(&format!(r#" {}="{}""#, a.qname(), c14n_attr(&a.value)));
        }
        out.push('>');
        for node in &self.children {
            match node {
                Node::Text(t) => out.push_str(&c14n_text(t)),
                Node::Element(e) => e.write_c14n(&scope, &rendered_here, inclusive, out),
            }
        }
        out.push_str(&format!("</{}>", self.qname()));
    }
}

pub fn escape_text(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('\r', "&#13;")
}

/// Escape an attribute value so that it survives a parser's attribute-value normalization.
pub fn escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
        .replace('\t', "&#9;")
        .replace('\n', "&#10;")
        .replace('\r', "&#13;")
}

fn c14n_text(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('\r', "&#xD;")
}

fn c14n_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
        .replace('\r', "&#xD;")
}

/// Parse a document into its root element. Comments and processing instructions are dropped and
/// DTDs are refused (no entity expansion, so no XXE).
pub fn parse(xml: &str) -> Result<Element, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<(Element, Scope)> = vec![];
    let mut root: Option<Element> = None;

    let open = |e: &quick_xml::events::BytesStart, outer: &Scope| -> Result<(Element, Scope), String> {
        let name = std::str::from_utf8(e.name().as_ref()).map_err(|_| "element name is not UTF-8")?.to_string();
        let (prefix, local) = split_qname(&name);
        let mut decls = vec![];
        let mut raw_attrs = vec![];
        for attr in e.attributes() {
            let attr = attr.map_err(|e| format!("invalid attribute: {e}"))?;
            let key = std::str::from_utf8(attr.key.as_ref()).map_err(|_| "attribute name is not UTF-8")?.to_string();
            let raw = std::str::from_utf8(&attr.value).map_err(|_| "attribute value is not UTF-8")?;
            // Attribute-value normalization (XML 1.0 §3.3.3): literal whitespace becomes spaces;
            // character references are expanded afterwards and so survive.
            let normalized = raw.replace("\r\n", " ").replace(['\r', '\n', '\t'], " ");
            let value = quick_xml::escape::unescape(&normalized)
                .map_err(|e| format!("invalid attribute value: {e}"))?
                .into_owned();
            if key == "xmlns" {
                decls.push((None, value));
            } else if let Some(p) = key.strip_prefix("xmlns:") {
                decls.push((Some(p.to_string()), value));
            } else {
                raw_attrs.push((key, value));
            }
        }
        let mut scope = outer.clone();
        for (p, uri) in &decls {
            scope.insert(p.clone(), uri.clone());
        }
        let resolve = |p: &Option<String>| -> Result<Option<String>, String> {
            match p.as_deref() {
                Some("xml") => Ok(Some(NS_XML.into())),
                Some(p) => {
                    scope.get(&Some(p.to_string())).cloned().map(Some).ok_or_else(|| format!("undeclared prefix '{p}'"))
                }
                None => Ok(scope.get(&None).cloned().filter(|u| !u.is_empty())),
            }
        };
        let ns = resolve(&prefix)?;
        let mut attrs = vec![];
        for (key, value) in raw_attrs {
            let (p, l) = split_qname(&key);
            // Unprefixed attributes are in no namespace, whatever the default namespace is.
            let ans = if p.is_some() { resolve(&p)? } else { None };
            attrs.push(Attr { prefix: p, local: l, ns: ans, value });
        }
        Ok((Element { prefix, local, ns, decls, attrs, children: vec![] }, scope))
    };

    loop {
        let event =
            reader.read_event().map_err(|e| format!("invalid XML at byte {}: {e}", reader.buffer_position()))?;
        match event {
            Event::Start(e) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(format!("elements are nested more than {MAX_DEPTH} deep"));
                }
                let outer = stack.last().map(|(_, s)| s.clone()).unwrap_or_default();
                stack.push(open(&e, &outer)?);
            }
            Event::Empty(e) => {
                let outer = stack.last().map(|(_, s)| s.clone()).unwrap_or_default();
                let (el, _) = open(&e, &outer)?;
                match stack.last_mut() {
                    Some((parent, _)) => parent.children.push(Node::Element(el)),
                    None if root.is_none() => root = Some(el),
                    None => return Err("more than one root element".into()),
                }
            }
            Event::End(_) => {
                let (el, _) = stack.pop().ok_or("unbalanced end tag")?;
                match stack.last_mut() {
                    Some((parent, _)) => parent.children.push(Node::Element(el)),
                    None if root.is_none() => root = Some(el),
                    None => return Err("more than one root element".into()),
                }
            }
            Event::Text(t) => {
                let text = t.xml10_content().map_err(|e| format!("invalid text: {e}"))?;
                push_text(&mut stack, &text);
            }
            Event::CData(t) => {
                let text = String::from_utf8_lossy(&t).replace("\r\n", "\n");
                push_text(&mut stack, &text);
            }
            Event::GeneralRef(r) => {
                let text = match r.resolve_char_ref().map_err(|e| format!("invalid character reference: {e}"))? {
                    Some(c) => c.to_string(),
                    None => {
                        let name = r.decode().map_err(|e| format!("invalid entity: {e}"))?;
                        match name.as_ref() {
                            "amp" => "&".into(),
                            "lt" => "<".into(),
                            "gt" => ">".into(),
                            "quot" => "\"".into(),
                            "apos" => "'".into(),
                            other => return Err(format!("unknown entity '&{other};'")),
                        }
                    }
                };
                push_text(&mut stack, &text);
            }
            Event::DocType(_) => return Err("DTDs are not allowed".into()),
            Event::Eof => break,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) => {}
        }
    }
    if !stack.is_empty() {
        return Err("unexpected end of document".into());
    }
    root.ok_or_else(|| "no root element".into())
}

fn push_text(stack: &mut [(Element, Scope)], text: &str) {
    let Some((parent, _)) = stack.last_mut() else { return };
    match parent.children.last_mut() {
        Some(Node::Text(prev)) => prev.push_str(text),
        _ => parent.children.push(Node::Text(text.to_string())),
    }
}

fn split_qname(name: &str) -> (Option<String>, String) {
    match name.split_once(':') {
        Some((p, l)) => (Some(p.to_string()), l.to_string()),
        None => (None, name.to_string()),
    }
}

/// Pretty-print a document for display, or return it unchanged if it doesn't parse.
pub fn pretty(xml: &str) -> String {
    match parse(xml) {
        Ok(el) => el.to_pretty(),
        Err(_) => xml.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "urn:a";
    const B: &str = "urn:b";

    #[test]
    fn round_trips_and_resolves_namespaces() {
        let xml = r#"<a:Root xmlns:a="urn:a" xmlns="urn:d" ID="x"><Child xmlns:b="urn:b" b:attr="1 &amp; 2">t&lt;&#x41;</Child><a:Empty/></a:Root>"#;
        let root = parse(xml).unwrap();
        assert!(root.is(A, "Root"));
        let child = root.find("urn:d", "Child").unwrap();
        assert_eq!(child.get_ns_attr(B, "attr"), Some("1 & 2"));
        assert_eq!(child.text_content(), "t<A");
        assert_eq!(root.to_xml(), xml.replace("&#x41;", "A"));
        assert!(parse("<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>").is_err());
        // Deep nesting is refused rather than overflowing the stack later.
        let deep = format!("{}{}", "<a>".repeat(100_000), "</a>".repeat(100_000));
        assert!(parse(&deep).unwrap_err().contains("nested"));
        let ok = format!("{}{}", "<a>".repeat(MAX_DEPTH), "</a>".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
    }

    #[test]
    fn exclusive_c14n_renders_only_utilized_namespaces() {
        // Example adapted from the exc-c14n spec: the unused prefix is dropped, attributes are
        // sorted by namespace URI then local name, and empty elements get end tags.
        let xml = r#"<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org"><n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org" b="2" a="1"/></n1:elem2></n0:local>"#;
        let root = parse(xml).unwrap();
        let elem2 = root.elements().next().unwrap();
        let outer = root.scope_within(&Scope::new());
        assert_eq!(
            elem2.exc_c14n(&outer, &[]),
            r#"<n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org" a="1" b="2"></n3:stuff></n1:elem2>"#
        );
        // An inclusive prefix in scope is rendered on the apex.
        assert!(elem2.exc_c14n(&outer, &["n0".into()]).starts_with(r#"<n1:elem2 xmlns:n0="foo:bar" xmlns:n1="#));
    }

    #[test]
    fn built_trees_declare_what_they_use() {
        let mut el = Element::new(A, "a", "Root").child(
            Element::new(B, "", "Inner").ns_attr(A, "a", "flag", "y").child(Element::new(B, "", "Leaf").text("v")),
        );
        el.declare_namespaces();
        assert_eq!(
            el.to_xml(),
            r#"<a:Root xmlns:a="urn:a"><Inner xmlns="urn:b" a:flag="y"><Leaf>v</Leaf></Inner></a:Root>"#
        );
        let parsed = parse(&el.to_xml()).unwrap();
        assert_eq!(parsed.exc_c14n(&Scope::new(), &[]), el.exc_c14n(&Scope::new(), &[]));
    }
}
