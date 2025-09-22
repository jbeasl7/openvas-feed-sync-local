# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rarlab:winrar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836099");
  script_version("2025-04-08T05:43:28+0000");
  script_cve_id("CVE-2025-31334");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-08 05:43:28 +0000 (Tue, 08 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-07 11:11:48 +0530 (Mon, 07 Apr 2025)");
  script_name("RARLabs WinRAR Symbolic Mark of the Web Security Bypass Vulnerability - Windows");

  script_tag(name:"summary", value:"WinRAR is prone to a symbolic link mark of
  the web bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an inadequate
  validation of symbolic links in the context of Window's Mark of the Web
  mechanism.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"RARLabs WinRAR prior to version 7.11 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 7.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN59547048/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_winrar_detect.nasl");
  script_mandatory_keys("WinRAR/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.11")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.11", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);