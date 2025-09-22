# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803765");
  script_version("2025-09-05T15:40:40+0000");
  script_cve_id("CVE-2013-1035");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-09-27 15:45:01 +0530 (Fri, 27 Sep 2013)");
  script_name("Apple iTunes ActiveX Control Memory Corruption Vulnerability - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error within an ActiveX Control.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary code or cause denial of service.");

  script_tag(name:"affected", value:"Apple iTunes prior to version 11.1 on Windows.");

  script_tag(name:"solution", value:"Update to version 11.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5936");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62486");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54893");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Sep/84");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
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

if(version_is_less(version:version, test_version:"11.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"11.1", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
