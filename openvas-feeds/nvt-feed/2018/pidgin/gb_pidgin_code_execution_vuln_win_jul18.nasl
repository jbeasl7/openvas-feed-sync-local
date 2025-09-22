# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pidgin:pidgin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813735");
  script_version("2024-02-27T14:36:53+0000");
  script_cve_id("CVE-2017-2640");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-27 14:36:53 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-07-30 16:05:18 +0530 (Mon, 30 Jul 2018)");
  script_name("Pidgin 'Out-of-Bounds Write' Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"Pidgin is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  write error while decoding invalid xml.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"Pidgin before version 2.12.0.");

  script_tag(name:"solution", value:"Update to version 2.12.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://pidgin.im/news/security/?id=109");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96775");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2.12.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.12.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
