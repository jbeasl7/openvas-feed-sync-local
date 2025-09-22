# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834622");
  script_version("2024-10-18T15:39:59+0000");
  script_cve_id("CVE-2024-7788");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-18 15:39:59 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-25 19:56:45 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-23 15:26:01 +0530 (Mon, 23 Sep 2024)");
  script_name("LibreOffice Improper Digital Signature Invalidation Vulnerability (Sep 2024) - Linux");

  script_tag(name:"summary", value:"LibreOffice is prone to an improper
  digital signature invalidation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an incorrect digital
  signature validation during the repair of corrupt zip files in
  LibreOffice.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to exploit the repair mechanism to bypass signature verification.");

  script_tag(name:"affected", value:"LibreOffice version before 24.2.5
  on Linux.");

  script_tag(name:"solution", value:"Update to version 24.2.5 or 24.8.0 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/CVE-2024-7788");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2024-7788");
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

if(version_is_less(version:version, test_version:"24.2.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"24.2.5 or 24.8.0", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
