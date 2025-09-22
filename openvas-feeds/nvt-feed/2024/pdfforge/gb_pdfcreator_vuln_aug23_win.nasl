# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124511");
  script_version("2024-04-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-04-08 05:05:41 +0000 (Mon, 08 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-03-12 09:00:00 +0200 (Tue, 12 Mar 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-14 14:48:46 +0000 (Fri, 14 Jul 2023)");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-36664");

  script_name("pdfforge PDFCreator < 5.1.2 Permission Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_pdfforge_pdfcreator_smb_login_detect.nasl");
  script_mandatory_keys("pdfforge/pdfcreator/detected");

  script_tag(name:"summary", value:"PDFCreator < 5.1.2 contains a vulnerable version of Ghostscript");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ghostscript, which is included in
  PDFCreator, does not properly handle permission validation for pipe devices. This could result
  in the execution of arbitrary commands if malformed document files are processed.");

  script_tag(name:"impact", value:"Successful exploitation could allow a remote attacker
  to cause a denial of service or escalate privileges.");

  script_tag(name:"affected", value:"PDFCreator before version 5.1.2");

  script_tag(name:"solution", value:"Update to version 5.1.2 or later.");

  script_xref(name:"URL", value:"https://www.pdfforge.org/blog/pdfcreator-5-1-2-is-out");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=706761");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

CPE = "cpe:/a:pdfforge:pdfcreator";

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.1.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.2", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
