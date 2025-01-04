//! Header chains are HTTP headers where each header value can contain
//! multiple records, and multiple headers can be appended.
//!
//! This module provides a set of types for managing header chains,
//! and their associated records.
//!
//! Header chains follow the spec for [RFC 7230](https://tools.ietf.org/html/rfc7230),
//! which defines the set of permitted and non-permitted tokens.

use std::{fmt::Debug, ops, str::FromStr};

use http::HeaderMap;

/// A header chain is a grouping of multiple header values,
/// all associated with a single header name.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct HeaderChain<T> {
    inner: Vec<Header<T>>,
}

impl<T> HeaderChain<T> {
    /// Create a new header chain.
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Append a header to the chain.
    pub fn push_header<H>(&mut self, header: H)
    where
        H: Into<Header<T>>,
    {
        self.inner.push(header.into());
    }

    /// Append a record to the last header in the chain.
    ///
    /// If no headers exist, a new header is created.
    pub fn push_record<R>(&mut self, record: R)
    where
        R: Into<Record<T>>,
    {
        if let Some(last) = self.inner.last_mut() {
            last.push(record.into());
        } else {
            self.push_header(Header::single(record));
        }
    }
}

impl<T> HeaderChain<T>
where
    T: ParseChainRecord,
{
    /// Create a new header chain from the headers in the given headers map.
    pub fn from_headers(name: http::HeaderName, headers: &HeaderMap) -> Self {
        let entries = headers.get_all(&name);

        let mut inner = Vec::new();
        for entry in entries {
            let header =
                Header::from_header_value(entry).expect("header value to be a valid header value");
            inner.push(header);
        }

        Self { inner }
    }
}

impl<T: Debug> Debug for HeaderChain<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HeaderChain").field(&self.inner).finish()
    }
}

impl<T> ops::Deref for HeaderChain<T> {
    type Target = [Header<T>];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> FromIterator<Header<T>> for HeaderChain<T> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Header<T>>,
    {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}

impl<T> FromIterator<Record<T>> for HeaderChain<T> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Record<T>>,
    {
        Self {
            inner: vec![Header::from_iter(iter)],
        }
    }
}

impl<T> FromIterator<T> for HeaderChain<T> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        Self {
            inner: vec![Header::from_iter(iter)],
        }
    }
}

mod iterchain {

    use std::iter::Flatten;

    use super::*;

    pub struct HeaderChainIter<'a, T>(std::slice::Iter<'a, Header<T>>);

    impl<'a, T> Iterator for HeaderChainIter<'a, T> {
        type Item = &'a Header<T>;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }

    impl<T> Debug for HeaderChainIter<'_, T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("HeaderChainIter").finish()
        }
    }

    pub struct HeaderChainIntoIter<T>(std::vec::IntoIter<Header<T>>);

    impl<T> Iterator for HeaderChainIntoIter<T> {
        type Item = Header<T>;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }

    impl<T> Debug for HeaderChainIntoIter<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("HeaderChainIntoIter").finish()
        }
    }

    pub struct HeaderChainFlatIter<'a, T>(Flatten<std::slice::Iter<'a, Header<T>>>);

    impl<'a, T> Iterator for HeaderChainFlatIter<'a, T> {
        type Item = &'a Record<T>;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }

    impl<T> Debug for HeaderChainFlatIter<'_, T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("HeaderChainFlatIter").finish()
        }
    }

    pub struct HeaderChainFlatIntoIter<T>(Flatten<std::vec::IntoIter<Header<T>>>);

    impl<T> Iterator for HeaderChainFlatIntoIter<T> {
        type Item = Record<T>;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }

    impl<T> Debug for HeaderChainFlatIntoIter<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("HeaderChainFlatIntoIter").finish()
        }
    }

    impl<'a, T> IntoIterator for &'a HeaderChain<T> {
        type Item = &'a Header<T>;
        type IntoIter = HeaderChainIter<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            HeaderChainIter(self.inner.iter())
        }
    }

    impl<T> IntoIterator for HeaderChain<T> {
        type Item = Header<T>;
        type IntoIter = HeaderChainIntoIter<T>;

        fn into_iter(self) -> Self::IntoIter {
            HeaderChainIntoIter(self.inner.into_iter())
        }
    }

    impl<T> HeaderChain<T> {
        /// Iterator over the individual records in all headers in the chain.
        pub fn flat_iter(&self) -> iterchain::HeaderChainFlatIter<'_, T> {
            iterchain::HeaderChainFlatIter(self.inner.iter().flatten())
        }

        /// Owned iterator over the individual records in all headers in the chain.
        pub fn flat_into_iter(self) -> iterchain::HeaderChainFlatIntoIter<T> {
            iterchain::HeaderChainFlatIntoIter(self.inner.into_iter().flatten())
        }
    }

    impl<T> HeaderChain<T> {
        /// Convert the header chain into a single header with all records.
        pub fn flatten(self) -> HeaderChain<T> {
            Self {
                inner: vec![self.flat_into_iter().collect()],
            }
        }

        /// Convert the header chain into multiple headers, each with a single record.
        pub fn expand(self) -> HeaderChain<T> {
            Self {
                inner: self.flat_into_iter().map(Header::single).collect(),
            }
        }

        /// Keep only the last record in the header in the chain.
        pub fn keep_last(self) -> HeaderChain<T> {
            Self {
                inner: self
                    .flat_into_iter()
                    .last()
                    .map(Header::single)
                    .into_iter()
                    .collect(),
            }
        }

        /// Keep only the first record in the header in the chain.
        pub fn keep_first(self) -> HeaderChain<T> {
            Self {
                inner: self
                    .flat_into_iter()
                    .next()
                    .map(Header::single)
                    .into_iter()
                    .collect(),
            }
        }
    }
}

impl<T> HeaderChain<T>
where
    T: ChainRecord,
{
    /// Set the headers in the given headers map.
    pub fn set_headers(self, headers: &mut HeaderMap) {
        for header in self.into_iter() {
            let value = header.into_record_value();
            headers.append(T::HEADER_NAME, value);
        }
    }

    /// Append the record to the headers in the given headers map
    pub fn append_record<R>(mode: &AppendHeaderRecordMode, record: R, headers: &mut http::HeaderMap)
    where
        R: Into<Record<T>>,
        T: Debug,
    {
        let mut chain = Self::from_headers(T::HEADER_NAME, headers);
        headers.remove(T::HEADER_NAME);

        match mode {
            AppendHeaderRecordMode::Append => {
                chain.push_header(Header::single(record));
                chain.set_headers(headers);
            }
            AppendHeaderRecordMode::Chain => {
                chain.push_record(record);
                chain.set_headers(headers);
            }
            AppendHeaderRecordMode::Flatten => {
                chain.push_record(record);
                chain.flatten().set_headers(headers);
            }
            AppendHeaderRecordMode::Expand => {
                let header = Header::single(record);
                chain.push_header(header);
                chain.expand().set_headers(headers);
            }
            AppendHeaderRecordMode::KeepLast => {
                chain.push_header(Header::single(record));
                chain.keep_last().set_headers(headers);
            }
            AppendHeaderRecordMode::KeepFirst => {
                chain.push_header(Header::single(record));
                chain.keep_first().set_headers(headers);
            }
        }
    }
}

#[cfg(test)]
mod chain_tests {

    use super::*;

    #[test]
    fn manipulate_header_chain() {
        let mut chain = HeaderChain::new();
        assert_eq!(chain.len(), 0);
        assert_eq!(chain.flat_iter().count(), 0);

        chain.push_header(Header::single("text/html"));
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.flat_iter().count(), 1);

        chain.push_record("application/json");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.flat_iter().count(), 2);

        chain.push_header(Header::single("application/xml"));
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.flat_iter().count(), 3);

        chain = chain.flatten();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.flat_iter().count(), 3);

        chain = chain.expand();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.flat_iter().count(), 3);

        chain = chain.keep_last();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], Header::single("application/xml"));
    }

    #[test]
    fn construct_from_iter() {
        let chain: HeaderChain<&str> = vec!["text/html", "application/json", "application/xml"]
            .into_iter()
            .map(Header::single)
            .collect();

        assert_eq!(chain.len(), 3);
        assert_eq!(chain.flat_iter().count(), 3);

        let chain = vec!["text/html", "application/json", "application/xml"]
            .into_iter()
            .collect::<HeaderChain<&str>>();

        assert_eq!(chain.len(), 1);
        assert_eq!(chain.flat_iter().count(), 3);
    }
}

/// A record header is a header value with multiple
/// records separated by a delimiter.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct Header<T> {
    inner: Vec<Record<T>>,
}

impl<T> Header<T> {
    /// Create a new header with no records.
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Create a new header with the given capacity for records.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    /// Create a new header with a single record.
    pub fn single<R>(record: R) -> Self
    where
        R: Into<Record<T>>,
    {
        Self {
            inner: vec![record.into()],
        }
    }

    /// Append a record to the header.
    pub fn push(&mut self, record: Record<T>) {
        self.inner.push(record);
    }
}

impl<T> Header<T>
where
    T: ParseChainRecord,
{
    /// Create a `Header<T>` from a header value, parsing the records.
    pub fn from_header_value(value: &http::HeaderValue) -> Result<Self, T::Error> {
        let value = value.as_bytes();
        let mut records = Vec::new();

        for record in value.split(|&byte| byte == T::DELIMITER) {
            records.push(
                Record::parse_record(record)
                    .expect("value to parse must have been a valid HTTP header"),
            );
        }

        Ok(Self { inner: records })
    }
}

impl<T: Debug> Debug for Header<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Headers").field(&self.inner).finish()
    }
}

mod iterheader {
    use super::*;

    #[derive(Debug)]
    pub struct HeaderIter<'a, T>(std::slice::Iter<'a, Record<T>>);

    impl<'a, T> Iterator for HeaderIter<'a, T> {
        type Item = &'a Record<T>;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }

    impl<'a, T> IntoIterator for &'a Header<T> {
        type Item = &'a Record<T>;
        type IntoIter = HeaderIter<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            HeaderIter(self.inner.iter())
        }
    }

    #[derive(Debug)]
    pub struct HeaderIntoIter<T>(std::vec::IntoIter<Record<T>>);

    impl<T> Iterator for HeaderIntoIter<T> {
        type Item = Record<T>;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }

    impl<T> IntoIterator for Header<T> {
        type Item = Record<T>;
        type IntoIter = HeaderIntoIter<T>;

        fn into_iter(self) -> Self::IntoIter {
            HeaderIntoIter(self.inner.into_iter())
        }
    }

    impl<T> Header<T> {
        /// Iterator over the individual records in the header.
        pub fn iter(&self) -> HeaderIter<'_, T> {
            HeaderIter(self.inner.iter())
        }
    }

    impl<T> FromIterator<Record<T>> for Header<T> {
        fn from_iter<I>(iter: I) -> Self
        where
            I: IntoIterator<Item = Record<T>>,
        {
            Self {
                inner: iter.into_iter().collect(),
            }
        }
    }

    impl<T> FromIterator<T> for Header<T> {
        fn from_iter<I>(iter: I) -> Self
        where
            I: IntoIterator<Item = T>,
        {
            Self {
                inner: iter.into_iter().map(Record::from_value).collect(),
            }
        }
    }
}

impl<T> ops::Deref for Header<T> {
    type Target = [Record<T>];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod header_tests {

    use super::*;

    #[test]
    fn manipulate_header() {
        let mut header = Header::new();
        assert_eq!(header.len(), 0);

        header.push(Record::from_value("text/html"));
        assert_eq!(header.len(), 1);

        header.push(Record::from_value("application/json"));
        assert_eq!(header.len(), 2);

        header.push(Record::from_value("application/xml"));
        assert_eq!(header.len(), 3);

        let header = header.into_iter().collect::<Header<&str>>();
        assert_eq!(header.len(), 3);
    }
}

/// A record is a single value in a header chain.
///
/// It is usually deliminated by a comma, but can be deliminated
/// by any character.
///
/// This record object holds either the parsed value `T`, or a raw
/// header value. This allows headers to be parsed lazily, and for
/// invalid header records to be passed through.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Record<T>(RecordEntry<T>);

impl<T> Debug for Record<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            RecordEntry::Value(value) => f.debug_tuple("Record::Value").field(value).finish(),
            RecordEntry::Raw(header_value) => {
                f.debug_tuple("Record::Raw").field(header_value).finish()
            }
        }
    }
}

/// A record entry is either a parsed value, or a raw header value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecordEntry<T> {
    /// A parsed value.
    Value(T),

    /// A raw header value.
    Raw(Vec<u8>),
}

impl<T> Record<T> {
    /// Create a new record with the given `T` value.
    pub fn from_value(value: T) -> Self {
        Self(RecordEntry::Value(value))
    }

    /// Map the record value to a new value, preserving the raw value if it exists.
    pub fn map<U, F>(self, f: F) -> Record<U>
    where
        F: FnOnce(T) -> U,
    {
        Record(match self.0 {
            RecordEntry::Value(value) => RecordEntry::Value(f(value)),
            RecordEntry::Raw(value) => RecordEntry::Raw(value),
        })
    }

    /// Create a new record with the given raw header value.
    ///
    /// This is private because it assumes that the raw value consists
    /// only of bytes that are valid in a header value.
    fn from_raw(value: Vec<u8>) -> Self {
        // debug_assert!(
        //     value.iter().all(|c| is_valid(*c)),
        //     "Raw header values must be valid header bytes"
        // );
        //TODO: Validate bytes?

        Self(RecordEntry::Raw(value))
    }

    /// Get a reference to the record entry.
    pub fn entry(&self) -> &RecordEntry<T> {
        &self.0
    }

    /// Consume this record, returning the inner entry.
    pub fn into_entry(self) -> RecordEntry<T> {
        self.0
    }

    /// Get a reference to the record value `T`.
    pub fn value(&self) -> Option<&T> {
        match &self.0 {
            RecordEntry::Value(value) => Some(value),
            RecordEntry::Raw(_) => None,
        }
    }

    /// Get a reference to the raw header value.
    pub fn raw(&self) -> Option<&[u8]> {
        match &self.0 {
            RecordEntry::Value(_) => None,
            RecordEntry::Raw(value) => Some(value),
        }
    }

    /// Convert the record into the value `T`.
    pub fn into_value(self) -> Option<T> {
        match self.0 {
            RecordEntry::Value(value) => Some(value),
            RecordEntry::Raw(_) => None,
        }
    }

    /// Convert the record into the raw header value.
    pub fn into_raw(self) -> Option<Vec<u8>> {
        match self.0 {
            RecordEntry::Value(_) => None,
            RecordEntry::Raw(value) => Some(value),
        }
    }
}

impl<T> ParseChainRecord for Record<T>
where
    T: ParseChainRecord,
{
    const DELIMITER: u8 = T::DELIMITER;
    type Error = T::Error;

    fn parse_record(value: &[u8]) -> Result<Self, T::Error> {
        Ok(T::parse_record(value)
            .map(Record::from_value)
            .unwrap_or_else(|_| Record::from_raw(value.to_vec())))
    }
}

impl<T> From<http::HeaderValue> for Record<T>
where
    T: ParseChainRecord,
{
    fn from(value: http::HeaderValue) -> Self {
        match T::parse_record(value.as_bytes()) {
            Ok(record) => record.into(),
            Err(_) => Record::from_raw(value.as_bytes().to_vec()),
        }
    }
}

impl<T> FromStr for Record<T>
where
    T: ParseChainRecord,
{
    type Err = T::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Record::parse_record(s.as_bytes())
    }
}

impl<T> From<T> for Record<T> {
    fn from(value: T) -> Self {
        Self::from_value(value)
    }
}

impl<T> ToChainRecord for Record<T>
where
    T: ToChainRecord,
{
    const HEADER_NAME: http::header::HeaderName = T::HEADER_NAME;

    fn into_bytes(self) -> Vec<u8> {
        match self.0 {
            RecordEntry::Value(value) => value.into_bytes(),
            RecordEntry::Raw(value) => value,
        }
    }

    fn into_header_value(self) -> http::HeaderValue {
        match self.0 {
            RecordEntry::Value(value) => value.into_header_value(),
            RecordEntry::Raw(value) => http::HeaderValue::from_bytes(&value)
                .expect("Records should always contain valid http Header values"),
        }
    }
}

/// This trait is used to convert a `Header<T>` or `HeaderChain<T>` into a
/// http::HeaderValue.
pub trait IntoRecordValue<T>
where
    T: ChainRecord,
{
    /// Convert the value into a header value.
    fn into_record_value(self) -> http::HeaderValue;

    /// Insert the header into the given headers map, replacing any existing headers.
    fn insert_header(self, headers: &mut HeaderMap) -> Option<http::HeaderValue>
    where
        Self: Sized,
    {
        headers.insert(T::HEADER_NAME, self.into_record_value())
    }

    /// Append the header to the given headers map.
    fn append_header(self, headers: &mut HeaderMap) -> bool
    where
        Self: Sized,
    {
        headers.append(T::HEADER_NAME, self.into_record_value())
    }
}

impl<T, I> IntoRecordValue<T> for I
where
    I: IntoIterator<Item = Record<T>>,
    T: ChainRecord,
{
    fn into_record_value(self) -> http::HeaderValue {
        let records = self.into_iter().map(|record| record.into_bytes());
        http::HeaderValue::from_bytes(
            &records
                .collect::<Vec<_>>()
                .join([T::DELIMITER, b' '].as_slice()),
        )
        .expect("Header records must always return bytes which are valid in HTTP Headers")
    }
}

/// This trait is used to convert a `Record<T>` into a `http::HeaderValue`.
pub trait ToChainRecord: Sized {
    /// The header name associated with this record.
    const HEADER_NAME: http::header::HeaderName;

    /// Convert the record into a byte representation.
    fn into_bytes(self) -> Vec<u8>;

    /// Convert the record into a header value.
    fn into_header_value(self) -> http::HeaderValue {
        http::HeaderValue::from_bytes(&self.into_bytes())
            .expect("Header values should always be valid HTTP header values")
    }

    /// Insert the header into the given headers map, replacing any existing headers.
    fn insert_header(self, headers: &mut HeaderMap) {
        headers.insert(Self::HEADER_NAME, self.into_header_value());
    }

    /// Append the header to the given headers map.
    fn append_header(self, headers: &mut HeaderMap) {
        headers.append(Self::HEADER_NAME, self.into_header_value());
    }
}

/// This trait is used to parse a `Record<T>` from a `http::HeaderValue`.
pub trait ParseChainRecord {
    /// The delimiter used to separate records in a header value.
    const DELIMITER: u8;

    /// Error returned when parsing a record fails.
    type Error: std::error::Error;

    /// Parse a record from a byte representation into the record type.
    fn parse_record(value: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// This trait represents a typed record in a header chain.
///
/// It combines the `ToChainRecord` and `ParseChainRecord` traits,
/// and is implemented for any type that implements both.
pub trait ChainRecord: ToChainRecord + ParseChainRecord {
    /// Create a new header chain from the headers in the given headers map.
    fn chain_from_headers(headers: &http::HeaderMap) -> HeaderChain<Self>
    where
        Self: Sized,
    {
        HeaderChain::from_headers(Self::HEADER_NAME, headers)
    }
}

impl<T> ChainRecord for T where T: ToChainRecord + ParseChainRecord {}

/// This trait is used to convert a http::Request into a type.
pub trait FromRequest {
    /// Convert the request into a type.
    fn from_request<B>(req: &http::Request<B>) -> Self
    where
        Self: Sized;
}

/// How to append a single record to a `http::HeaderMap`
/// when the record is part of a header chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum AppendHeaderRecordMode {
    /// Append the record as a new header.
    #[default]
    Append,

    /// Append the record to the last header in the chain.
    Chain,

    /// Flatten all of the headers into a single header, appending the record there.
    Flatten,

    /// Expand all of the headers into separate headers, appending the record to a new header.
    Expand,

    /// Keep only the last header in the chain, implicitly meaning only the new record.
    KeepLast,

    /// Keep only the first header in the chain, or if there are no headers, create a new header with
    /// the new record.
    KeepFirst,
}
