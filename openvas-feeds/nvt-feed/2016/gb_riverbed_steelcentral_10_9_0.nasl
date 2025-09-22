# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:riverbed:steelcentral";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105790");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-06-30 17:13:33 +0200 (Thu, 30 Jun 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-34112");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Riverbed SteelCentral NetProfiler & NetExpress Virtual Editions < 10.9.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_riverbed_steelcentral_version.nasl");
  script_mandatory_keys("riverbed/SteelCentral/installed", "riverbed/SteelCentral/is_vm",
                        "riverbed/SteelCentral/model");

  script_tag(name:"summary", value:"The Riverbed SteelCentral NetProfiler and NetExpress virtual
  appliances are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - authentication bypass

  - SQL injection

  - arbitrary code execution via command injection

  - privilege escalation

  - local file inclusion

  - cross-site scripting

  - account hijacking

  - hardcoded default credentials");

  script_tag(name:"affected", value:"SteelCentral NetProfiler versions through 10.8.7 and
  SteelCentral NetExpress versions through 10.8.7.");

  script_tag(name:"solution", value:"Update to version 10.9.0 or later.");

  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/Riverbed-SteelCentral-NetProfilerNetExpress-Advisory.pdf");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40108");
  script_xref(name:"URL", value:"https://support.riverbed.com/content/support/software/steelcentral-npm/net-profiler.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! get_kb_item( "riverbed/SteelCentral/is_vm" ) )
  exit( 0 );

if( ! model = get_kb_item( "riverbed/SteelCentral/model" ) )
  exit( 0 );

if( model !~ "^SCNE" && model !~ "^SCNP" )
  exit( 99 );

if( ! vers = get_app_version( cpe:CPE, service:"consolidated_version" ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"10.9.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.9.0" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
