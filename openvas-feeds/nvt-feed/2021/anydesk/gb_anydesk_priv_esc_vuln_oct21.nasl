# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:anydesk:anydesk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146932");
  script_version("2024-02-07T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-02-07 05:05:18 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"creation_date", value:"2021-10-18 12:13:27 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-20 18:46:00 +0000 (Wed, 20 Oct 2021)");

  script_cve_id("CVE-2021-40854");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("AnyDesk Desktop Privilege Escalation Vulnerability (Oct 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_anydesk_desktop_consolidation.nasl");
  script_mandatory_keys("anydesk/desktop/smb-login/detected");

  script_tag(name:"summary", value:"AnyDesk Desktop is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"AnyDesk Desktop for Windows allows for a local escalation of
  privileges through the UI. When a connection has been accepted, the user can click the 'Open Chat
  Log' link in the connection window. This will open Notepad with escalated privileges. The user can
  then use the 'File -> Open...' dialog, to start any application as administrator.");

  script_tag(name:"impact", value:"A user with restricted privileges can use AnyDesk to obtain
  administrator privileges.

  Note: the vulnerability can not be exploited remotely because AnyDesk blocks remote interaction
  with the chat window.");

  script_tag(name:"affected", value:"AnyDesk Desktop version 3.1.0 through 6.3.2 (excluding 6.2.6)
  on Windows.");

  script_tag(name:"solution", value:"Update to version 6.2.6, 6.3.3 or later.");

  script_xref(name:"URL", value:"https://anydesk.com/cve/2021-40854/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_greater_equal(version: version, test_version: "3.1.0") &&
    version_is_less(version: version, test_version: "6.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.6", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^6\.3\." && version_is_less(version: version, test_version: "6.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.3", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
