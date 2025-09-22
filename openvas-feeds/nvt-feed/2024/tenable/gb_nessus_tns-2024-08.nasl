# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126776");
  script_version("2024-05-23T05:05:28+0000");
  script_tag(name:"last_modification", value:"2024-05-23 05:05:28 +0000 (Thu, 23 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-21 07:46:50 +0000 (Tue, 21 May 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2024-3289", "CVE-2024-3290");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Multiple Vulnerabilities (TNS-2024-08)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-3289: When installing Nessus to a directory outside of the default location on a
  Windows host, Nessus did not enforce secure permissions for sub-directories. This could allow for
  local privilege escalation if users had not secured the directories in the non-default
  installation location.

  - CVE-2024-3290: A race condition exists where an authenticated, local attacker on a Windows
  Nessus host could modify installation parameters at installation time, which could lead to the
  execution of arbitrary code on the Nessus host.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.7.3.");

  script_tag(name:"solution", value:"Update to version 10.7.3 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2024-08");

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

if( version_is_less( version:version, test_version:"10.7.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.7.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );