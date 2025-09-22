# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804247");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-03-17 18:31:41 +0530 (Mon, 17 Mar 2014)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2013-2214");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios 'status.cgi' Information Disclosure Vulnerability (Jul 2013) - Active Check");

  # nb: Only a standard request to an existing and valid URL so no ACT_ATTACK required
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_http_detect.nasl");
  script_mandatory_keys("nagios/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Nagios is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists in status.cgi which fails to restrict access to
  all service groups");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information.");

  script_tag(name:"affected", value:"Nagios version 3.x prior to 3.5.1 and 4.0 prior to
  4.0 beta4.");

  script_tag(name:"solution", value:"Update to version 4.0 beta4, 3.5.1 or later.

  Note: There are also indicators that this could be a security misconfiguration which is not solved
  by software updates. Please consider contacting the vendor for additional information on possible
  mitigations.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q3/54");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210123011532/https://www.securityfocus.com/bid/60814/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20160413200008/http://tracker.nagios.org/view.php?id=456");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/cgi-bin/status.cgi?servicegroup=all&style=grid";

req = http_get(port: port, item:url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" &&
    "Status Grid For All Service Groups" >< res && "Current Network Status" >< res  &&
    "you do not have permission to view information for any of the hosts you requested" >!< res) {
  body = http_extract_body_from_response(data: res);
  report = "It was possible to obtain potential sensitive information via '" +
           http_report_vuln_url(port: port, url: url, url_only: TRUE) + "'." +
           '\n\nResult:\n\n' + chomp(body);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
