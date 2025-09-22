# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811796");
  script_version("2025-05-29T05:40:25+0000");
  script_cve_id("CVE-2015-3419");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-26 17:37:00 +0000 (Tue, 26 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-10-04 13:06:11 +0530 (Wed, 04 Oct 2017)");
  script_name("vBulletin 5.x <= 5.1.6 'Private Messages' Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"vBulletin is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an input validation failure.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  messages into existing conversations without authorization.");

  script_tag(name:"affected", value:"vBulletin versions 5.x through 5.1.6.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  # nb: Not possible to detect the patched versions
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("vbulletin_http_detect.nasl");
  script_mandatory_keys("vbulletin/detected");

  script_xref(name:"URL", value:"https://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/4319488-security-patch-released-for-vbulletin-5-1-4-5-1-6-and-vbulletin-cloud");
  script_xref(name:"URL", value:"http://members.vbulletin.com/patches.php");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.1.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Apply Patch", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
