# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834862");
  script_version("2025-01-10T05:38:09+0000");
  script_cve_id("CVE-2024-12425", "CVE-2024-12426");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-10 05:38:09 +0000 (Fri, 10 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-08 14:28:13 +0530 (Wed, 08 Jan 2025)");
  script_name("LibreOffice Multiple Vulnerabilities (Jan 2025) - Linux");

  script_tag(name:"summary", value:"LibreOffice is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-12425: Path traversal leading to arbitrary .ttf file write

  - CVE-2024-12426: URL fetching can be used to exfiltrate arbitrary INI file values and environment variables");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to disclose environmental variables and arbitrary INI file values and conduct
  path traversal attacks.");

  script_tag(name:"affected", value:"LibreOffice version 24.8 before 24.8.4 on
  Linux.");

  script_tag(name:"solution", value:"Update to version 24.8.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2024-12425");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2024-12426");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_libre_office_detect_lin.nasl");
  script_mandatory_keys("LibreOffice/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range_exclusive(version:vers, test_version_lo:"24.8", test_version_up:"24.8.4")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "24.8.4", install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);