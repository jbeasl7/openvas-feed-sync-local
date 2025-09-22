# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113265");
  script_version("2025-02-21T15:40:05+0000");
  script_tag(name:"last_modification", value:"2025-02-21 15:40:05 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-09-07 15:01:31 +0200 (Fri, 07 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11616");

  script_name("Foxmail <= 7.2.9.115 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tencent_foxmail_smb_login_detect.nasl");
  script_mandatory_keys("foxmail/detected");

  script_tag(name:"summary", value:"Tencent Foxmail is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user visiting a malicious page or open a
  malicious file could allow an attacker to execute code under the context of the current process.
  The flaw exists within the processing of URI handlers and results from a lack of proper
  validation of a user-supplied string before using it to execute a system call.");

  script_tag(name:"affected", value:"Tencent Foxmail through version 7.2.9.115.");

  script_tag(name:"solution", value:"Update to version 7.2.9.116 or above.");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-18-584/");

  exit(0);
}

CPE = "cpe:/a:tencent:foxmail";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE ) )
  exit( 0 );

if( version_is_less( version: version, test_version: "7.2.9.116" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.2.9.116" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
