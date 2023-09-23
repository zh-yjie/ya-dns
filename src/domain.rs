use publicsuffix::{List, Psl};

#[derive(Debug)]
pub struct DomainSuffix {
    list: List,
}

impl DomainSuffix {
    pub fn new(suffix_list: &str) -> Self {
        match suffix_list.parse() {
            Ok(list) => Self { list },
            Err(_) => Self { list: List::new() },
        }
    }

    pub fn contains(&self, domain: &str) -> bool {
        let labels = domain.as_bytes().rsplit(|x| *x == b'.');
        self.list.find(labels).typ.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_suffix_match() {
        let ds = DomainSuffix::new("// BEGIN ICANN DOMAINS\ndomain.geek\nbbs\n");
        assert_eq!(ds.contains("domain.geek"), true);
        assert_eq!(ds.contains("www.domain.geek"), true);
        assert_eq!(ds.contains("domain.bbs"), true);
        assert_eq!(ds.contains("domain.abc"), false);
    }
}
