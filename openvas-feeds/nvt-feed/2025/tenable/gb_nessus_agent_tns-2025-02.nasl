# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131479");
  script_version("2025-04-04T05:39:39+0000");
  script_tag(name:"last_modification", value:"2025-04-04 05:39:39 +0000 (Fri, 04 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-03-21 10:29:58 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-24915");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Agent Privilege Escalation Vulnerability (TNS-2025-02, TNS-2025-03)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_tenable_nessus_agent_detect_smb.nasl");
  script_mandatory_keys("tenable/nessus_agent/win/detected");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus Agent installed in a non-default location on a Windows
  host, does not enforce secure permissions for sub-directories. This could allow for local
  privilege escalation if users had not secured the directories in the non-default installation
  location.");

  script_tag(name:"affected", value:"Tenable Nessus Agent prior to version 10.7.4 and 10.8.x prior
  to 10.8.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 10.7.4, 10.8.3 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2025-02");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2025-03");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"10.7.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.7.4", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"10.8", test_version_up:"10.8.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.8.3", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
