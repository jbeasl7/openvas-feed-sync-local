# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834217");
  script_version("2024-07-25T05:05:41+0000");
  script_cve_id("CVE-2024-5261");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-25 05:05:41 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-03 11:20:09 +0530 (Wed, 03 Jul 2024)");
  script_name("LibreOffice Improper Certificate Validation Vulnerability (Jul 2024) - Linux");

  script_tag(name:"summary", value:"LibreOffice is prone to an improper
  certificate validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to TLS certificate
  is not properly verified when utilizing LibreOfficeKit.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform man-in-the-middle attacks, potentially intercepting or modifying
  data transmitted between LibreOffice (when used in LibreOfficeKit mode) and
  remote servers.");

  script_tag(name:"affected", value:"LibreOffice prior to version 24.2.4 on
  Linux.");

  script_tag(name:"solution", value:"Update to version 24.2.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2024-5261");
  script_xref(name:"URL", value:"https://feedly.com/cve/CVE-2024-5261");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_libre_office_detect_lin.nasl");
  script_mandatory_keys("LibreOffice/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"24.2.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"24.2.4", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
