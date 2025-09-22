# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:application_policy_infrastructure_controller";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105535");
  script_cve_id("CVE-2015-4235");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("2025-01-21T05:37:33+0000");

  script_name("Cisco Application Policy Infrastructure Controller Access Control Vulnerability (cisco-sa-20150722-apic)");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150722-apic");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75994");

  script_tag(name:"impact", value:"An exploit could allow the attacker to gain access to the APIC as the root user and perform root-level commands.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to improper implementation of access controls in the APIC filesystem. An attacker could exploit this vulnerability by accessing the cluster management configuration of the APIC.");
  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"summary", value:"A vulnerability in the cluster management configuration of the Cisco Application Policy Infrastructure Controller (APIC) could allow an authenticated, remote attacker to access the APIC as the root user.");
  script_tag(name:"affected", value:"Application Policy Infrastructure Controllers running software versions prior to 1.1(1j), 1.0(3o) and 1.0(4o).");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-02-10 12:54:47 +0100 (Wed, 10 Feb 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_apic_web_detect.nasl");
  script_mandatory_keys("cisco/application_policy_infrastructure_controller/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

vulnerable_versions = make_list( "1.0(1e)",
                                 "1.0(1h)",
                                 "1.0(1k)",
                                 "1.0(1n)",
                                 "1.0(2j)",
                                 "1.0(2m)",
                                 "1.0(2n)",
                                 "1.0(3f)",
                                 "1.0(3i)",
                                 "1.0(3k)",
                                 "1.0(3n)",
                                 "1.0(4h)",
                                 "1.1(1i)",
                                 "1.1(1h)",
                                 "1.1(1g)",
                                 "1.1(1f)",
                                 "1.1(1e)");

foreach v ( vulnerable_versions )
{
  if( vers == v )
  {
      report = report_fixed_ver( installed_version:vers, fixed_version:'See vendor advisory' );
      security_message( port:port, data:report );
      exit (0 );
  }
}

exit( 99 );
