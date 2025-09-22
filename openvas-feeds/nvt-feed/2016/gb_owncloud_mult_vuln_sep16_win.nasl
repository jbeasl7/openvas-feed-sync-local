# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809292");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-4718", "CVE-2015-4717");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-09-23 15:12:02 +0530 (Fri, 23 Sep 2016)");
  script_name("ownCloud Multiple Vulnerabilities (Sep 2016) - Windows");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - The external SMB storage of ownCloud was not properly neutralizing all
    special elements.

  - The filename sanitization component does not properly handle $_GET
    parameters cast by PHP to an array");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to execute arbitrary SMB commands and to cause a denial
  of service.");

  script_tag(name:"affected", value:"ownCloud Server before 6.0.8, 7.0.x
  before 7.0.6, and 8.0.x before 8.0.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade ownCloud server 6.0.8, 7.0.6, 8.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-008");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76161");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-007");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/detected", "Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version =~ "^[6-8]") {

  if(version_is_less(version:version, test_version:"6.0.8")) {
    fix = "6.0.8";
    VULN = TRUE;
  }

  else if(version_in_range(version:version, test_version:"7.0.0", test_version2:"7.0.5")) {
    fix = "7.0.6";
    VULN = TRUE;
  }

  else if(version_in_range(version:version, test_version:"8.0.0", test_version2:"8.0.3")) {
    fix = "8.0.4";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
