# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:anydesk:anydesk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813554");
  script_version("2024-02-07T05:05:18+0000");
  script_cve_id("CVE-2018-13102");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-07 05:05:18 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-11 17:23:00 +0000 (Tue, 11 Sep 2018)");
  script_tag(name:"creation_date", value:"2018-07-06 16:47:10 +0530 (Fri, 06 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");

  script_name("AnyDesk Desktop < 4.1.3 DLL Preloading Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"AnyDesk Desktop is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to improper sanitization of an unknown
  function in the component DLL Loader.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to escalate
  privileges and gain control of the application.");

  script_tag(name:"affected", value:"AnyDesk Desktop versions before 4.1.3 on Windows 7 SP1.");

  script_tag(name:"solution", value:"Update to version 4.1.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://download.anydesk.com/changelog.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_anydesk_desktop_consolidation.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("anydesk/desktop/smb-login/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("secpod_reg.inc");

if (hotfix_check_sp(win7: 1) <= 0)
  exit(99);

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.3", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
