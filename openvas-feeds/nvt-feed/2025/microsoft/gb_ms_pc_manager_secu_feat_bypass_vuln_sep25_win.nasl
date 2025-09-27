# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:pc_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836688");
  script_version("2025-09-26T15:41:32+0000");
  script_cve_id("CVE-2025-49728");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-26 15:41:32 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-16 19:15:35 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-25 10:42:23 +0530 (Thu, 25 Sep 2025)");
  script_name("Microsoft PC Manager Security Feature Bypass Vulnerability (Sep 2025) - Windows");

  script_tag(name:"summary", value:"Microsoft PC Manager is prone to a
  security feature bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to bypass a security feature locally.");

  script_tag(name:"affected", value:"Microsoft PC Manager prior to version 3.18.0.0 on Microsoft Windows.");

  script_tag(name:"solution", value:"Update to version 3.18.0.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-49728");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_pc_manager_detect_win.nasl");
  script_mandatory_keys("PCManager/Win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"3.18.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.18.0.0", install_path: location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
