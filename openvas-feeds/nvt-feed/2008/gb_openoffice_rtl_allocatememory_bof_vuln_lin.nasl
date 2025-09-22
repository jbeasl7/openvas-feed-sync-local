# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openoffice:openoffice.org";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800010");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-10-01 17:01:16 +0200 (Wed, 01 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2152");
  script_name("OpenOffice.org < 2.4.1 rtl_allocateMemory Heap Based BOF Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_openoffice_ssh_login_detect.nasl");
  script_mandatory_keys("openoffice.org/linux/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30599");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29622");
  script_xref(name:"URL", value:"http://www.openoffice.org/security/cves/CVE-2008-2152.html");
  script_xref(name:"URL", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=714");

  script_tag(name:"summary", value:"OpenOffice.org is prone to a heap based buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is in alloc_global.c file in which rtl_allocateMemory
  function rounding up allocation requests to be aligned on a 8 byte boundary without checking the
  rounding results in an integer overflow condition.");

  script_tag(name:"impact", value:"Exploitation will result in buffer overflows via a specially
  crafted document and allow remote unprivileged user who provides a OpenOffice.org document that
  is opened by a local user to execute arbitrary commands on the system with the privileges of the
  user running OpenOffice.org.");

  script_tag(name:"affected", value:"OpenOffice.org 2.x and prior.");

  script_tag(name:"solution", value:"Update to version 2.4.1 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"2.4.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.4.1" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
