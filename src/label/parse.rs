use nom::{
    IResult,
    branch::alt,
    bytes::complete::take_while1,
    character::complete::char,
    combinator::map,
    multi::separated_list1,
    sequence::{delimited, separated_pair},
};

use crate::label::{AttrReq, Clause, Label};

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn ident(input: &str) -> IResult<&str, &str> {
    take_while1(is_ident_char)(input)
}

fn attr_req(input: &str) -> IResult<&str, AttrReq> {
    map(separated_pair(ident, char('='), ident), |(k, v)| AttrReq {
        key: k.to_string(),
        value: v.to_string(),
    })(input)
}

fn clause(input: &str) -> IResult<&str, Clause> {
    alt((
        delimited(char('('), separated_list1(char('|'), attr_req), char(')')),
        map(attr_req, |r| vec![r]),
    ))(input)
}

fn label_expr(input: &str) -> IResult<&str, Label> {
    if input.trim() == "true" {
        return Ok((
            "",
            Label {
                clauses: vec![],
                always_true: true,
            },
        ));
    }

    map(separated_list1(char('&'), clause), |clauses| Label {
        clauses,
        always_true: false,
    })(input)
}

pub fn parse(expr: &str) -> std::result::Result<Label, String> {
    let trimmed = expr.trim();
    match label_expr(trimmed) {
        Ok(("", label)) => Ok(label),
        Ok((rest, _)) => Err(format!("unexpected trailing: {rest}")),
        Err(e) => Err(format!("parse error: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let label = parse("role=admin").unwrap();
        assert_eq!(label.clauses.len(), 1);
        assert_eq!(label.clauses[0].len(), 1);
    }

    #[test]
    fn parse_or_group() {
        let label = parse("(role=admin|role=auditor)").unwrap();
        assert_eq!(label.clauses.len(), 1);
        assert_eq!(label.clauses[0].len(), 2);
    }

    #[test]
    fn parse_and_of_ors() {
        let label = parse("(role=admin|role=auditor)&team=finance").unwrap();
        assert_eq!(label.clauses.len(), 2);
    }
}
