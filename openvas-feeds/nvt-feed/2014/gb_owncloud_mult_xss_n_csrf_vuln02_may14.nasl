# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804277");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2013-0300", "CVE-2013-0298");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-05-05 11:00:11 +0530 (Mon, 05 May 2014)");
  script_name("ownCloud Multiple XSS & CSRF Vulnerabilities -02 (May 2014)");

  script_tag(name:"summary", value:"ownCloud is prone to multiple cross-site scripting and cross-
  site request forgery (CSRF) vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper validation of user-supplied input passed via 'mountpoint' parameter
upon submission to the /apps/files_external/addMountPoint.php script, 'dir' and
'file' parameters upon submission to the /apps/files_pdfviewer/viewer.php script
and 'iCalendar' file in the calendar application.

  - Insufficient validation of user-supplied input passed via the 'v' POST
parameter to changeview.php within /apps/calendar/ajax, multiple unspecified
parameters to addRootCertificate.php, dropbox.php and google.php scripts within
/apps/files_external/ajax and multiple unspecified POST parameters to
settings.php script within /apps/user_webdavauth.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct request forgery
attacks and execute arbitrary script code in a user's browser.");
  script_tag(name:"affected", value:"ownCloud Server before version 4.5.x before 4.5.7");
  script_tag(name:"solution", value:"Update to version 4.5.7 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q1/378");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58103");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58107");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-004");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-003");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"4.5.0", test_version2:"4.5.6")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"4.5.0 - 4.5.6");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
