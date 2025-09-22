# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gimp:gimp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836059");
  script_version("2025-03-26T05:38:58+0000");
  script_cve_id("CVE-2023-44441", "CVE-2023-44442", "CVE-2023-44443", "CVE-2023-44444");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-26 05:38:58 +0000 (Wed, 26 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-21 16:12:37 +0530 (Fri, 21 Mar 2025)");
  script_name("GIMP Multiple Vulnerabilities (Mar25) - Windows");

  script_tag(name:"summary", value:"GIMP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2023-44441: GIMP DDS File Parsing Heap-based Buffer Overflow Remote Code Execution Vulnerability

  - CVE-2023-44442: GIMP PSD File Parsing Heap-based Buffer Overflow Remote Code Execution Vulnerability

  - CVE-2023-44443: GIMP PSP File Parsing Integer Overflow Remote Code Execution Vulnerability

  - CVE-2023-44444: GIMP PSP File Parsing Off-By-One Remote Code Execution Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute remote code.");

  script_tag(name:"affected", value:"GIMP version 2.10.34 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.10.36 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.gimp.org/news/2023/11/07/gimp-2-10-36-released/#fixed-vulnerabilities");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");

  script_dependencies("gb_gimp_detect.nasl");
  script_mandatory_keys("Gimp/Win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"2.10.34")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.10.36", install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);