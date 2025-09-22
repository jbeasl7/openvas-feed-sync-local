# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openoffice:openoffice.org";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90029");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-09-09 22:57:12 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 02:18:21 +0000 (Thu, 08 Feb 2024)");
  script_cve_id("CVE-2008-2152", "CVE-2008-3282");
  script_name("OpenOffice.org <= 2.4.1 Multiple Vulnerabilities - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openoffice_ssh_login_detect.nasl");
  script_mandatory_keys("openoffice.org/linux/detected");

  script_xref(name:"URL", value:"https://www.openoffice.org/security/cves/CVE-2008-2152.html");

  script_tag(name:"summary", value:"OpenOffice.org is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The remote host is probably affected by the vulnerabilities described in
  CVE-2008-2152 or CVE-2008-3282 on 64-bit platform's:

  - CVE-2008-2152: Integer overflow in the rtl_allocateMemory function in
  sal/rtl/source/alloc_global.c in OpenOffice.org (OOo) 2.0 through 2.4 allows remote attackers to
  execute arbitrary code via a crafted file that triggers a heap-based buffer overflow.

  - CVE-2008-3282: Integer overflow in the rtl_allocateMemory function in
  sal/rtl/source/alloc_global.c in the memory allocator in OpenOffice.org (OOo) 2.4.1, on 64-bit
  platforms, allows remote attackers to cause a denial of service (application crash) or possibly
  execute arbitrary code via a crafted document, related to a 'numeric truncation error' a different
  vulnerability than CVE-2008-2152.");

  script_tag(name:"solution", value:"Update to version 3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"3.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.0" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
