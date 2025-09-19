use publicsuffix::{List, Psl};
use std::{io, str::FromStr};

#[derive(Debug)]
pub struct DomainSuffix {
    list: List,
}

impl DomainSuffix {
    pub fn contains(&self, domain: &str) -> bool {
        let labels = domain.as_bytes().rsplit(|x| *x == b'.');
        self.list.find(labels).typ.is_some()
    }
}

impl FromStr for DomainSuffix {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let list = match s.parse() {
            Ok(list) => Self { list },
            Err(_) => Self { list: List::new() },
        };
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_suffix_match() {
        let ds: DomainSuffix = "// BEGIN ICANN DOMAINS\ndomain.geek\nbbs\n"
            .parse()
            .unwrap();
        assert_eq!(ds.contains("domain.geek"), true);
        assert_eq!(ds.contains("www.domain.geek"), true);
        assert_eq!(ds.contains("domain.bbs"), true);
        assert_eq!(ds.contains("domain.abc"), false);
    }
}
