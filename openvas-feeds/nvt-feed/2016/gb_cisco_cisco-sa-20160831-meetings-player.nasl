# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:webex_wrf_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107067");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2016-1464");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-10-25 11:19:11 +0530 (Tue, 25 Oct 2016)");

  script_name("Cisco WebEx Meetings Player Arbitrary Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"Cisco WebEx Meetings Player is prone to
an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of user-supplied files. An
attacker could exploit this vulnerability by persuading a user to open a malicious file by using the affected
software.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to execute arbitrary code on
the system with the privileges of the user.");

  script_tag(name:"affected", value:"Cisco WebEx WRF Player T29 SP10 Base Windows.");

  script_tag(name:"solution", value:"Updates are available from the Cisco WebEx Meetings Server where the
player was installed from, see advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160831-meetings-player");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_webexwrf_detect_win.nasl");
  script_mandatory_keys("Cisco/Wrfplayer/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_in_range(version: vers, test_version:"29", test_version2:"29.13.111") ||
    version_in_range(version: vers, test_version:"30", test_version2:"30.12.0") ||
    version_in_range(version: vers, test_version:"31", test_version2:"31.5.19")) {
   report = report_fixed_ver(installed_version: vers, fixed_version: "See advisory", install_path: path);
   security_message( port:0, data:report );
   exit(0);
}

exit(99);
