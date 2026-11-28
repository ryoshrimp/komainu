//! Global-reachability check used to block SSRF destinations.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns `true` only for addresses that are safe to connect to from the public internet's point of view.
pub(crate) fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || (a == 100 && (64..=127).contains(&b))
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // ::ffff:0:0/96 (IPv4-mapped), ::ffff:0:0:0/96 (IPv4-translated) and 64:ff9b::/96 (NAT64):
    // judge by the embedded IPv4.
    let embedded = |ip: Ipv6Addr| {
        let o = ip.octets();
        Ipv4Addr::new(o[12], o[13], o[14], o[15])
    };
    if s[..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
        return is_global_v4(embedded(ip));
    }
    if s[..4] == [0, 0, 0, 0] && s[4] == 0xffff && s[5] == 0 {
        return is_global_v4(embedded(ip));
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return is_global_v4(embedded(ip));
    }
    // ::/96 (IPv4-compatible, deprecated) also covers :: and ::1.
    !(s[..6] == [0, 0, 0, 0, 0, 0]
        || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)
        || (s[0] == 0x100 && s[1..4] == [0, 0, 0])
        || (s[0] == 0x2001 && s[1] < 0x200)
        || (s[0] == 0x2001 && s[1] == 0xdb8)
        || s[0] == 0x2002
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xff00) == 0xff00)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn non_global_ranges_are_rejected_at_both_ends() {
        let ranges = [
            ("0.0.0.0", "0.255.255.255"),
            ("10.0.0.0", "10.255.255.255"),
            ("100.64.0.0", "100.127.255.255"),
            ("127.0.0.0", "127.255.255.255"),
            ("169.254.0.0", "169.254.255.255"),
            ("172.16.0.0", "172.31.255.255"),
            ("192.0.0.0", "192.0.0.255"),
            ("192.0.2.0", "192.0.2.255"),
            ("192.88.99.0", "192.88.99.255"),
            ("192.168.0.0", "192.168.255.255"),
            ("198.18.0.0", "198.19.255.255"),
            ("198.51.100.0", "198.51.100.255"),
            ("203.0.113.0", "203.0.113.255"),
            ("224.0.0.0", "239.255.255.255"),
            ("240.0.0.0", "255.255.255.255"),
            ("::", "::"),
            ("::1", "::1"),
            ("::", "::255.255.255.255"),
            ("::ffff:0:0", "::ffff:255.255.255.255"),
            ("64:ff9b::", "64:ff9b::255.255.255.255"),
            ("64:ff9b:1::", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff"),
            ("2002::", "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ("100::", "100::ffff:ffff:ffff:ffff"),
            ("2001::", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
            ("fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ("fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ("ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ];
        for (first, last) in ranges {
            assert!(!is_global(ip(first)), "{first}");
            assert!(!is_global(ip(last)), "{last}");
        }
    }

    #[test]
    fn embedded_ipv4_is_judged_by_the_ipv4_rules() {
        assert!(!is_global(ip("::ffff:127.0.0.1")));
        assert!(!is_global(ip("64:ff9b::10.0.0.1")));
        assert!(!is_global(ip("::ffff:0:10.0.0.1")));
        assert!(!is_global(ip("::ffff:0:127.0.0.1")));
        assert!(is_global(ip("::ffff:0:8.8.8.8")));
        assert!(is_global(ip("::ffff:8.8.8.8")));
        assert!(is_global(ip("64:ff9b::8.8.8.8")));
    }

    #[test]
    fn neighbours_of_non_global_ranges_are_global() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "2606:4700::1111",
            "2001:200::1",
            "2001:db9::1",
            "fec0::",
            "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe00::",
            "100:0:0:1::",
            "::1:0:0",
            "64:ff9b:2::",
            "2001:4860::8888",
            "2003::",
        ] {
            assert!(is_global(ip(s)), "{s}");
        }
    }
}
