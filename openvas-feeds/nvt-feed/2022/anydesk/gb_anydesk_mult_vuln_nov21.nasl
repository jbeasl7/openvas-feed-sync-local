# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:anydesk:anydesk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126141");
  script_version("2024-02-07T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-02-07 05:05:18 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-09-16 06:58:43 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-16 15:09:00 +0000 (Fri, 16 Sep 2022)");

  script_cve_id("CVE-2021-44425", "CVE-2021-44426");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("AnyDesk Desktop Multiple Vulnerabilities (Nov 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_anydesk_desktop_consolidation.nasl");
  script_mandatory_keys("anydesk/desktop/smb-login/detected");

  script_tag(name:"summary", value:"AnyDesk Desktop is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-44425: The attacker is able to compromise the service listening to the port and
  possibly advance further within the secure corporate network and access sensitive data.

  - CVE-2021-44426: The attacker can persuade a victim to connect to the same remote computer,
  and then plant the malicious file in the victim's filesystem without the victim knowledge.");

  script_tag(name:"affected", value:"AnyDesk Desktop version 6.3.x through 6.3.5 on Windows.");

  script_tag(name:"solution", value:"Update to version 6.3.5 or later.");

  script_xref(name:"URL", value:"https://anydesk.com/en/changelog/windows");
  script_xref(name:"URL", value:"https://argus-sec.com/discovering-tunneling-service-security-flaws-in-anydesk-remote-application/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "6.3.0", test_version2: "6.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.5", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
