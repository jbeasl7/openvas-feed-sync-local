# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:solarwinds:dameware_mini_remote_control";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107381");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-11-26 13:45:13 +0100 (Mon, 26 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-8220");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SolarWinds DameWare Mini Remote Control < 12.0 Hotfix 1 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_solarwinds_dameware_mini_rc_smb_login_detect.nasl");
  script_mandatory_keys("solarwinds/dameware_mini_remote_control/detected");

  script_tag(name:"summary", value:"SolarWinds DameWare Mini Remote Control is prone to a local
  buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Stack-based buffer overflow in the URI handler in DWRCC.exe.");

  script_tag(name:"impact", value:"Exploitation of this vulnerability allows remote attackers to
  execute arbitrary code via a crafted commandline argument in a link.");

  script_tag(name:"affected", value:"SolarWinds DameWare Mini Remote Control prior to version 12.0
  Hotfix 1.");

  script_tag(name:"solution", value:"Update to version 12.0 Hotfix 1 or later.");

  script_xref(name:"URL", value:"https://thwack.solarwinds.com/thread/95643");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less_equal(version: vers, test_version: "12.0.0.509")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "12.0 Hotfix 1", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
