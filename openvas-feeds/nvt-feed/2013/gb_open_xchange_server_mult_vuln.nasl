# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803182");
  script_version("2024-04-05T15:38:49+0000");
  script_tag(name:"last_modification", value:"2024-04-05 15:38:49 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"creation_date", value:"2013-03-18 10:14:58 +0530 (Mon, 18 Mar 2013)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2013-1646", "CVE-2013-1647", "CVE-2013-1648", "CVE-2013-1650",
                "CVE-2013-1651");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Open-Xchange Server Multiple Vulnerabilities (Mar 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_open-xchange_ox_app_suite_http_detect.nasl");
  script_mandatory_keys("open-xchange/app_suite/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Open-Xchange Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Input passed via arbitrary GET parameters to /servlet/TestServlet is not properly sanitized
  before being returned to the user.

  - Input related to the 'Source' field when creating subscriptions is not properly sanitized
  before being used. This can be exploited to perform arbitrary HTTP GET requests to remote and
  local servers.

  - The OXUpdater component does not properly validate the SSL certificate of an update server.
  This can be exploited to spoof update packages via a MitM (Man-in-the-Middle) attack.

  - The application creates the /opt/open-exchange/etc directory with insecure world-readable
  permissions. This can be exploited to disclose certain sensitive information.

  - Input passed via the 'location' GET parameter to /ajax/redirect is not properly sanitized
  before being used to construct HTTP response headers.

  - Certain input related to RSS feed contents is not properly sanitized before being used. This
  can be exploited to insert arbitrary HTML and script code.");

  script_tag(name:"affected", value:"Open-Xchange Server versions prior to 6.20.7-rev14,
  6.22.0-rev13 and 6.22.1-rev14.");

  script_tag(name:"solution", value:"Update to versions 6.20.7-rev14, 6.22.0-rev13, 6.22.1-rev14
  or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52603");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58465");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58470");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58473");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58475");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Mar/74");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24791");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120785");

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

url = dir + "/servlet/TestServlet?foo=<script>alert(document.cookie)</script>";

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document\.cookie\)</script>")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
