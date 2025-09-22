# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100085");
  script_version("2024-08-09T05:05:42+0000");
  script_cve_id("CVE-2009-1171");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"creation_date", value:"2009-03-28 19:13:00 +0100 (Sat, 28 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Moodle File Disclosure Vulnerability (Mar 2009)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("Moodle/Version");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210118035335/http://www.securityfocus.com/archive/1/502231/30/0/threaded");

  script_tag(name:"summary", value:"Moodle is prone to a file disclousure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An input filter for TeX formulas can be exploited to disclose
  files readable by the web server. This includes the moodle configuration file with all
  authentication data and server locations for directly connecting to backend database.

  TeX filter by default is off and in case of being activated mostly no complete LaTeX environment
  on a server system will be available.");

  script_tag(name:"affected", value:"Moodle versions 1.6.x prior to 1.6.9, 1.7.x prior to 1.7.7,
  1.8.x prior to 1.8.9 and 1.9.x prior to 1.9.5.");

  script_tag(name:"solution", value:"Several alternatives:

  1) deactivate TeX filter, if not needed

  2) use more restrictive mimetex program for rendering

  3) change LaTeX configuration (set 'openin_any=p' for paranoid!)

  or upgrade to latest development version where patch should be applied by now.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"1.6", test_version2:"1.6.8") ||
   version_in_range(version:version, test_version:"1.7", test_version2:"1.7.6") ||
   version_in_range(version:version, test_version:"1.8", test_version2:"1.8.8") ||
   version_in_range(version:version, test_version:"1.9", test_version2:"1.9.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See references", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
