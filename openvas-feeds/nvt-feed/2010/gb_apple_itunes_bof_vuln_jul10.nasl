# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801409");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2010-1777");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_name("Apple iTunes 'itpc:' URI Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"iTunes is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the handling of 'itpc:' URL, when loaded by
  the user will trigger a buffer overflow and execute arbitrary code on the target system.");

  script_tag(name:"impact", value:"Successful exploitation could allow the attacker to execute
  arbitrary code in the context of an application. Failed exploit attempts will result in a
  denial-of-service condition.");

  script_tag(name:"affected", value:"Apple iTunes version prior to 9.2.1.");

  script_tag(name:"solution", value:"Update to version 9.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://isc.sans.edu/diary.html?storyid=9202");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41789");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jul/1024220.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_apple_itunes_smb_login_detect.nasl");
  script_mandatory_keys("apple/itunes/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"9.2.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"9.2.1", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
