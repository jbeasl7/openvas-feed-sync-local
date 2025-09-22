# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openvpn:openvpn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834298");
  script_version("2024-09-13T05:05:46+0000");
  script_cve_id("CVE-2024-24974", "CVE-2024-27459", "CVE-2024-27903", "CVE-2024-1305");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-11 14:46:26 +0000 (Thu, 11 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-08-13 18:43:29 +0530 (Tue, 13 Aug 2024)");
  script_name("OpenVPN Multiple Vulnerabilities (Aug 2024) - Windows");

  script_tag(name:"summary", value:"OpenVPN is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-1305: Potential integer overflow in !TapSharedSendPacket.

  - CVE-2024-24974: Disallows remote access to the service pipe for the interactive service
  component of OpenVPN GUI for Windows.

  - CVE-2024-27459: Privilege escalation in the interactive service component.

  - CVE-2024-27903: Disallow loading of plugins from untrusted installation paths.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to run arbitrary code
  and gain escalated privileges.");

  script_tag(name:"affected", value:"OpenVPN version 2.6.9 and prior.");

  script_tag(name:"solution", value:"Update to version 2.6.10 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.mail-archive.com/openvpn-users@lists.sourceforge.net/msg07534.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openvpn_win_detect.nasl");
  script_mandatory_keys("OpenVPN/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less(version: vers, test_version: "2.6.10")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.6.10", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
