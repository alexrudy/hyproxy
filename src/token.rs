use thiserror::Error;

const RFC_7230_TOKEN_SPECIAL: [char; 15] = [
    '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~',
];

pub(crate) fn is_rfc7230_token(item: &str) -> bool {
    item.chars()
        .all(|c| c.is_ascii_alphanumeric() || RFC_7230_TOKEN_SPECIAL.contains(&c))
}

#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[error("invalid RFC-7230 token")]
pub struct InvalidToken(pub String);

#[allow(dead_code)]
pub(crate) fn rfc7230_token(item: &str) -> Result<&str, InvalidToken> {
    if is_rfc7230_token(item) {
        Ok(item)
    } else {
        Err(InvalidToken(item.to_string()))
    }
}

pub(crate) fn rfc7230_protocol(item: &str) -> Result<&str, InvalidToken> {
    if item
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || RFC_7230_TOKEN_SPECIAL.contains(&c) || c == '/')
    {
        Ok(item)
    } else {
        Err(InvalidToken(item.to_string()))
    }
}
