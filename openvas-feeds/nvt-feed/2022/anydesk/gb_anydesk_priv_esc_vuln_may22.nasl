# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:anydesk:anydesk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148542");
  script_version("2024-02-07T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-02-07 05:05:18 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-07-29 04:15:29 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-22 14:33:00 +0000 (Fri, 22 Jul 2022)");

  script_cve_id("CVE-2022-32450");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("AnyDesk Desktop Privilege Escalation Vulnerability (May 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_anydesk_desktop_consolidation.nasl");
  script_mandatory_keys("anydesk/desktop/smb-login/detected");

  script_tag(name:"summary", value:"AnyDesk Desktop is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"AnyDesk Desktop on Windows allows a local user to gain SYSTEM
  privileges via a symbolic link because the user can write to their own %APPDATA% folder (used for
  ad.trace and chat) but the product runs as SYSTEM when writing chat-room data there.");

  script_tag(name:"affected", value:"AnyDesk Desktop version 7.0.13 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2022/Jun/44");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2022/Jul/9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "7.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
