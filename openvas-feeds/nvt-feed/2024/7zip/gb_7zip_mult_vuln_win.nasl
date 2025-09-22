# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:7-zip:7-zip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834219");
  script_version("2024-09-18T05:05:35+0000");
  script_cve_id("CVE-2023-52168", "CVE-2023-52169");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-18 05:05:35 +0000 (Wed, 18 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-07-08 16:38:43 +0530 (Mon, 08 Jul 2024)");
  script_name("7-Zip Multiple Vulnerabilities - Windows");

  script_tag(name:"summary", value:"7zip is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2023-52168: A heap-based overflow vulnerability

  - CVE-2023-52169: An out-of-bounds read vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to overwrite two bytes at multiple offsets beyond the allocated buffer size
  and to read beyond the intended buffer.");

  script_tag(name:"affected", value:"7zip version prior to 24.01 on Windows.");

  script_tag(name:"solution", value:"Update to version 24.01.");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/03/10");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_7zip_detect_portable_win.nasl");
  script_mandatory_keys("7zip/Win/Ver");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"24.01")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"24.01", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
