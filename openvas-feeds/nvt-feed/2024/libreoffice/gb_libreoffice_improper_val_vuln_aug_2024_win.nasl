# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834294");
  script_version("2024-10-18T15:39:59+0000");
  script_cve_id("CVE-2024-6472");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-18 15:39:59 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-08-08 13:02:08 +0530 (Thu, 08 Aug 2024)");
  script_name("LibreOffice Improper Certificate Validation Vulnerability (Aug 2024) - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to an improper
  certificate validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists when handling documents
  with signed macros inside.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to compromise the affected system.");

  script_tag(name:"affected", value:"LibreOffice version before 24.2.5 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 24.2.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2024-6472");
  script_xref(name:"URL", value:"https://www.cybersecurity-help.cz/vdb/SB20240805107");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_libre_office_detect_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"24.2.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"24.2.5", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
