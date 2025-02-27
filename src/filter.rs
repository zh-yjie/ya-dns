use crate::{
    config::{RequestRule, ResponseRule, RuleAction},
    handler_config::HandlerConfig
};
use hickory_proto::{op::LowerQuery, rr::RecordType};
use hickory_resolver::lookup::Lookup;
use log::debug;

pub fn check_response(
    cfg: &HandlerConfig,
    domain: &str,
    upstream_name: &str,
    resp: &Lookup,
) -> RuleAction {
    let answers = resp.records();

    // Drop empty response
    if answers.is_empty() {
        return RuleAction::Drop;
    }

    let check_upstream = |rule: &ResponseRule| {
        rule.upstreams
            .as_ref()
            .map(|u| u.iter().any(|s| s == upstream_name))
            .unwrap_or(true)
    };

    let check_ranges = |rule: &ResponseRule| {
        rule.ranges
            .as_ref()
            .map(|r| {
                r.iter().any(|range_pattern| {
                    // Process the leading `!`
                    let range_name = range_pattern.trim_start_matches('!');
                    let toggle = (range_pattern.len() - range_name.len()) % 2 == 1;

                    // See if the range contains the IP
                    let range = cfg.ranges.get(range_name);
                    range
                        .map(|range| {
                            answers
                                .iter()
                                .filter_map(|rec| match rec.record_type() {
                                    RecordType::A => {
                                        let ip = rec.data().unwrap().as_a().unwrap().0;
                                        Some(range.contains((ip).into()))
                                    }
                                    RecordType::AAAA => {
                                        let ip = rec.data().unwrap().as_aaaa().unwrap().0;
                                        Some(range.contains((ip).into()))
                                    }
                                    _ => None,
                                })
                                .next()
                                .unwrap_or(false)
                                ^ toggle // toggle result according to the number of !
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_or(true) // No ranges field means matching all ranges
    };

    cfg.response_rules
        .iter()
        .find(|rule| {
            check_upstream(rule) && check_ranges(rule) && check_domains(cfg, domain, &rule.domains)
        })
        .map(|rule| rule.action)
        .unwrap_or(RuleAction::Accept)
}

pub fn resolvers(cfg: &HandlerConfig, query: &LowerQuery) -> Vec<String> {
    let name = query.name().to_string();

    let check_type = |rule: &RequestRule| {
        rule.types
            .as_ref()
            .map(|l| l.iter().any(|t| *t == query.query_type()))
            .unwrap_or(true)
    };

    let rule = cfg
        .request_rules
        .iter()
        .find(|r| check_domains(cfg, &name, &r.domains) && check_type(r));

    if let Some(rule) = rule {
        debug!("Query {} matches rule {:?}", name, rule);
        rule.upstreams.iter().map(String::clone).collect()
    } else {
        debug!("No rule matches for {}. Use defaults.", name);
        // If no rule matches, use defaults
        cfg.defaults.iter().map(String::clone).collect()
    }
}

fn check_domains(cfg: &HandlerConfig, domain: &str, domains: &Option<Vec<String>>) -> bool {
    let name = domain.trim_end_matches(".");
    domains
        .as_ref()
        .map(|d| {
            d.iter().any(|domains_pattern| {
                // Process the leading `!`
                let domains_tag = domains_pattern.trim_start_matches('!');
                let toggle = (domains_pattern.len() - domains_tag.len()) % 2 == 1;
                let domains = cfg.domains.get(domains_tag);
                domains
                    .map(|domains| {
                        (domains.regex_set.is_match(&name) || domains.suffix.contains(&name))
                            ^ toggle
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(true) // No domains field means matching all domains
}
