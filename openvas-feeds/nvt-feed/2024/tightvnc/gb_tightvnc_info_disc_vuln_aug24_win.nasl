# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tightvnc:tightvnc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834434");
  script_version("2024-11-08T15:39:48+0000");
  script_cve_id("CVE-2024-42049");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-11-08 15:39:48 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-08-22 17:17:19 +0530 (Thu, 22 Aug 2024)");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_name("TightVNC Information Disclosure Vulnerability (Aug 2024) - Windows");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_tightvnc_detect_win.nasl");
  script_mandatory_keys("TightVNC/Win/Ver");

  script_xref(name:"URL", value:"https://www.recordedfuture.com/vulnerability-database/CVE-2024-42049");
  script_xref(name:"URL", value:"https://www.tightvnc.com/whatsnew.php");

  script_tag(name:"summary", value:"TightVNC is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper access control in
  TightVNC.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to gain unauthorized
  access to the control pipe through a network connection and obtain sensitive information.");

  script_tag(name:"affected", value:"TightVNC version prior to 2.8.84.");

  script_tag(name:"solution", value:"Update to version 2.8.84 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2.8.84")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.8.84", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
