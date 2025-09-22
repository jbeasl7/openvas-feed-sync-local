# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804289");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2013-1939");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-05-08 10:56:50 +0530 (Thu, 08 May 2014)");
  script_name("ownCloud 'SabreDAV' Local File Disclosure Vulnerability (oC-SA-2013-016) - Windows");

  script_tag(name:"summary", value:"ownCloud is prone to a local file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper checking of path separators in
  the base path within SabreDAV.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to download
  arbitrary files from the server and obtain sensitive information.");

  script_tag(name:"affected", value:"ownCloud 4.0.x through 4.0.13, 4.5.x through 4.5.8 and 5.0.x
  through 5.0.3 when running on Windows.");

  script_tag(name:"solution", value:"Update to version 4.0.14, 4.5.9, 5.0.4 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/04/11/3");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59027");
  script_xref(name:"URL", value:"https://github.com/owncloud/security-advisories/blob/master/server/oc-sa-2013-016.json");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.13") ||
   version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.8") ||
   version_in_range(version:vers, test_version:"5.0.0", test_version2:"5.0.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.0.14/4.5.9/5.0.4", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
