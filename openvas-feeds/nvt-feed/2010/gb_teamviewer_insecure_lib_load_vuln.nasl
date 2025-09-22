# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teamviewer:teamviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801436");
  script_version("2024-11-27T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-11-27 05:05:40 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"creation_date", value:"2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2010-3128");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamViewer File Opening Insecure Library Loading Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/detected");

  script_tag(name:"summary", value:"TeamViewer is prone to insecure library loading
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the application insecurely loading certain
  libraries from the current working directory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary code and conduct DLL hijacking attacks via a Trojan horse dwmapi.dll that is located in
  the same folder as a .tvs or .tvc file.");

  script_tag(name:"affected", value:"TeamViewer version 5.0.8703 and prior.");

  script_tag(name:"solution", value:"Update to version 5.0.9104 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41112");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14734/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2174");
  script_xref(name:"URL", value:"http://www.teamviewer.com/index.aspx");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "5.0.9104")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.9104", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
