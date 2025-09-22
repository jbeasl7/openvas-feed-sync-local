# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118008");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2021-04-07 14:50:26 +0200 (Wed, 07 Apr 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-02 19:56:00 +0000 (Fri, 02 Jul 2021)");

  script_cve_id("CVE-2021-20077", "CVE-2021-20079");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus <= 8.13.2 Privilege Escalation Vulnerability (TNS-2021-07)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tenable Nessus versions 8.13.2 and earlier were found to contain a
  privilege escalation vulnerability which could allow a Nessus administrator user to upload a
  specially crafted file that could lead to gaining administrator privileges on the Nessus host.");

  script_tag(name:"affected", value:"Tenable Nessus through version 8.13.2.");

  script_tag(name:"solution", value:"Update to version 8.14.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2021-07");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"8.14.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.14.0", install_path:location );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
