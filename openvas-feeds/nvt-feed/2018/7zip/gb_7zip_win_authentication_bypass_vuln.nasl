# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107311");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-05-11 16:01:22 +0200 (Fri, 11 May 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_cve_id("CVE-2018-10172");
  script_name("7zip Authentication Bypass Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_7zip_detect_portable_win.nasl");
  script_mandatory_keys("7zip/Win/Ver");
  script_tag(name:"summary", value:"7zip is prone to an authentication bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"7-Zip through 18.01 on Windows implements the Large memory pages option
  by calling the LsaAddAccountRights function to add the SeLockMemoryPrivilege privilege to the user's account,
  which makes it easier for attackers to bypass intended access restrictions by using this privilege in the
  context of a sandboxed process.");
  script_tag(name:"affected", value:"7zip through version 18.01.");
  script_tag(name:"solution", value:"Upgrade to 7zip version 18.03 or later.");
  script_xref(name:"URL", value:"https://sourceforge.net/p/sevenzip/discussion/45797/thread/e730c709/?limit=25&page=1#b240");
  exit(0);
}

CPE = "cpe:/a:7-zip:7-zip";

include ("host_details.inc");
include ("version_func.inc");

if (!infos = get_app_version_and_location (cpe:CPE, exit_no_version:TRUE)) {
  exit (0);
}

vers = infos ['version'];
path = infos ['location'];

if (version_is_less_equal (version:vers, test_version:"18.01")) {
  report = report_fixed_ver (installed_version:vers, fixed_version:"18.03", install_path:path);
  security_message(port:0, data:report);
  exit (0);
}

exit (99);
