# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ipswitch:ws_ftp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812071");
  script_version("2023-12-01T05:05:39+0000");
  script_cve_id("CVE-2017-16513");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2017-11-09 14:14:47 +0530 (Thu, 09 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-27 16:01:00 +0000 (Mon, 27 Nov 2017)");
  script_name("Ipswitch WS_FTP Professional < 12.6.0.3 Local Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_ipswitch_ws_ftp_pro_smb_login_detect.nasl");
  script_mandatory_keys("ipswitch/ws_ftp/professional/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43115");
  script_xref(name:"URL", value:"https://docs.ipswitch.com/WS_FTP126/ReleaseNotes/English/index.htm");

  script_tag(name:"summary", value:"Ipswitch WS_FTP Professional is prone to a local buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the application where some
  fields (local search and backup locations) allows users to input data and are not properly
  sanitized.");

  script_tag(name:"impact", value:"Successful exploitation will allow local attackers to conduct
  buffer overflow attacks on the affected system.");

  script_tag(name:"affected", value:"Ipswitch WS_FTP Professional prior to version 12.6.0.3.

  Note: Versions prior to 12.x were 2006 through 2007 which are assumed to be affected as well.");

  script_tag(name:"solution", value:"Update to version 12.6.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

# nb: See note in the affected tag above
if (version =~ "^200[67]" ||
    version_is_less(version:version, test_version:"12.6.0.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.6.0.3", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
