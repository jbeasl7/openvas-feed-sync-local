# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118009");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2021-23840", "CVE-2021-23841", "CVE-2021-20077");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-05 02:53:00 +0000 (Sun, 05 Jun 2022)");
  script_tag(name:"creation_date", value:"2021-04-08 12:07:17 +0200 (Thu, 08 Apr 2021)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Tenable Nessus Agent 7.2.0 - 8.2.2 Multiple Vulnerabilities (TNS-2021-04)");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The application was found to inadvertently capture the IAM role
  security token on the local host during initial linking of the Nessus Agent when installed on
  an Amazon EC2 instance. This could allow a privileged attacker to obtain the token.

  Additionally, one third-party component (OpenSSL) was found to contain vulnerabilities, and
  updated versions have been made available by the provider. Nessus Agent version 8.2.3 will
  update OpenSSL to 1.1.1j.");

  script_tag(name:"affected", value:"Tenable Nessus Agent version 7.2.0 through 8.2.2.");

  script_tag(name:"solution", value:"Update to version 8.2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2021-04-0");

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_tenable_nessus_agent_detect_smb.nasl");
  script_mandatory_keys("tenable/nessus_agent/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"7.2.0", test_version2:"8.2.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.2.3", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
