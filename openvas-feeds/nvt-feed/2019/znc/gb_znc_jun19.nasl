# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:znc:znc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108605");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-06-17 06:47:14 +0000 (Mon, 17 Jun 2019)");
  script_cve_id("CVE-2019-12816");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("ZNC < 1.7.4-rc1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_znc_consolidation.nasl");
  script_mandatory_keys("znc/detected");

  script_xref(name:"URL", value:"https://wiki.znc.in/ChangeLog/1.7.4");
  script_xref(name:"URL", value:"https://github.com/znc/znc/commit/8de9e376ce531fe7f3c8b0aa4876d15b479b7311");

  script_tag(name:"summary", value:"an ZNC IRC bouncer is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation allows remote authenticated non-admin users to escalate
  privileges and execute arbitrary code.");

  script_tag(name:"affected", value:"ZNC before 1.7.4-rc1.");

  script_tag(name:"solution", value:"Upgrade to ZNC 1.7.4-rc1 or later. Please see the references for more information.");

  script_tag(name:"insight", value:"The flaw can be triggered by loading a module with a crafted name.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"1.7.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.7.4-rc1" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
