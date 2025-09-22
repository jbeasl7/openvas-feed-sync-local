# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kaspersky:password_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812871");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-6306");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-22 14:38:00 +0000 (Tue, 22 May 2018)");
  script_tag(name:"creation_date", value:"2018-05-04 11:31:27 +0530 (Fri, 04 May 2018)");
  script_name("Kaspersky Password Manager DLL Hijacking Vulnerability (May 2018) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_kaspersky_password_manager_detect_win.nasl");
  script_mandatory_keys("kaspersky/password_manager/detected");

  script_xref(name:"URL", value:"https://support.kaspersky.com/vulnerability.aspx?el=12430#120418");

  script_tag(name:"summary", value:"Kaspersky Password Manager is prone to a DLL hijacking
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in an unknown function of
  the component DLL Handler.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to load a malicious DLL into the installer process and thereafter allow
  unauthorized code execution from the DLL.");

  script_tag(name:"affected", value:"Kaspersky Password Manager versions before
  8.0.6.538 on Windows.");

  script_tag(name:"solution", value:"Update to version 9.0.0.728 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"8.0.6.538")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.0.0.728", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
