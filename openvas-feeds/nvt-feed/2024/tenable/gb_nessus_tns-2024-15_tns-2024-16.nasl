# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118623");
  script_version("2024-09-18T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-09-18 05:05:35 +0000 (Wed, 18 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-17 09:13:37 +0000 (Tue, 17 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 14:28:41 +0000 (Wed, 04 Sep 2024)");

  script_cve_id("CVE-2024-6119", "CVE-2024-45491", "CVE-2024-45492");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Multiple Vulnerabilities (TNS-2024-15, TNS-2024-16)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus leverages third-party software to help provide underlying
  functionality. Several of the third-party components (OpenSSL, expat) were found to contain
  vulnerabilities, and updated versions have been made available by the providers.

  Nessus versions 10.7.6 and 10.8.3 are updating OpenSSL to version 3.0.15 and expat to version
  2.6.3 to address the identified vulnerabilities.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.7.6 and 10.8.x prior to
  10.8.3.");

  script_tag(name:"solution", value:"Update to version 10.7.6, 10.8.3 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2024-15");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2024-16");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"10.7.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.7.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"10.8.0", test_version_up:"10.8.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.8.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
