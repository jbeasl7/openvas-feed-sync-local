# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openvpn:openvpn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834899");
  script_version("2025-07-11T15:43:14+0000");
  script_cve_id("CVE-2024-5594");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-01-21 11:40:27 +0530 (Tue, 21 Jan 2025)");
  script_name("OpenVPN Improper Input Sanitization Vulnerability (Jan 2025) - Windows");

  script_tag(name:"summary", value:"OpenVPN is prone to an improper input
  sanitization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  sanitization of data received in PUSH_REPLY messages.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to inject unexpected arbitrary data into third-party executables or plug-ins.");

  script_tag(name:"affected", value:"OpenVPN version prior to version
  2.6.11.");

  script_tag(name:"solution", value:"Update to version 2.6.11 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://community.openvpn.net/openvpn/wiki/CVE-2024-5594");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if (version_is_less(version: vers, test_version: "2.6.11")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.6.11", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
