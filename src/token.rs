const RFC_7230_TOKEN_SPECIAL: [char; 15] = [
    '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~',
];

pub(crate) fn is_rfc7230_token(item: &str) -> bool {
    item.chars()
        .all(|c| c.is_ascii_alphanumeric() || RFC_7230_TOKEN_SPECIAL.contains(&c))
}
