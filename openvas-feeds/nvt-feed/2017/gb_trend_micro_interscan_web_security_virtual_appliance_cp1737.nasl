# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trendmicro:interscan_web_security_virtual_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140163");
  script_cve_id("CVE-2016-9269", "CVE-2016-9314", "CVE-2016-9315", "CVE-2016-9316");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Trend Micro InterScan Web Security Virtual Appliance 6.5 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1116672#");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version/build is present on the target host.");

  script_tag(name:"insight", value:"This update resolves multiple vulnerabilities in Trend Micro InterScan Web
  Security Virtual Appliance (IWSVA) 6.5 in which a remote attacker could potentially attain code execution.

  These include:

  - Remote Command Execution (RCE)

  - Privilege Escalation

  - Stored Cross Site Scripting (XSS) vulnerabilities");

  script_tag(name:"solution", value:"Update to version 6.5 CP 1737 or newer.");

  script_tag(name:"summary", value:"Trend Micro has released a new build of Trend Micro InterScan Web Security
  Virtual Appliance (IWSVA) 6.5. This build resolves vulnerabilities in the product that could potentially allow
  a remote attacker to execute artibtrary code on vulnerable installations.");

  script_tag(name:"affected", value:"Version 6.5");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-25 01:29:00 +0000 (Tue, 25 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-02-16 14:19:46 +0100 (Thu, 16 Feb 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.nasl");
  script_mandatory_keys("trendmicro/IWSVA/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! build = get_kb_item( "trendmicro/IWSVA/build" ) )
  exit( 0 );

if( vers == "6.5" && int( build ) < 1737 ) {
  report = report_fixed_ver( installed_version:vers, installed_build:build, fixed_version:"6.5", fixed_build:"1737" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
