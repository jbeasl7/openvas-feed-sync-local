# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:true_key";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813323");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-6661");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-04 01:58:00 +0000 (Sat, 04 Mar 2023)");
  script_tag(name:"creation_date", value:"2018-05-02 16:31:27 +0530 (Wed, 02 May 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("McAfee True Key DLL Side Loading Privilege Elevation Vulnerability - Windows");

  script_tag(name:"summary", value:"McAfee True Key is prone to a privilege elevation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to one of the True Key Service
  binaries loading a McAfee dynamic library in an insecure manner. An adversary could
  carefully craft an exploit to launch an Elevation of Privilege attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users to gain privilege elevation via not verifying a particular DLL file
  signature.");

  script_tag(name:"affected", value:"True Key version 4.20 and earlier.");

  script_tag(name:"solution", value:"Update to version 4.20.110 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://service.mcafee.com/webcenter/portal/cp/home/articleview?articleId=TS102801");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mcafee_true_key_detect_win.nasl");
  script_mandatory_keys("McAfee/TrueKey/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"4.20")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.20.110", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);