# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105147");
  script_cve_id("CVE-2014-8595", "CVE-2014-8866", "CVE-2014-8867", "CVE-2014-1666");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-26T05:05:09+0000");

  script_name("Citrix XenServer Multiple Security Updates (CTX200288)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX200288");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in Citrix XenServer.
  These vulnerabilities could, if exploited, allow unprivileged code in an HVM guest to gain privileged execution
  within that guest and also allow privileged code within a PV or HVM guest to crash the host or other guests.");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:

  - CVE-2014-8595: Missing privilege level checks in x86 emulation of far branches

  - CVE-2014-8866: Excessive checking in compatibility mode hypercall argument translation

  - CVE-2014-8867: Insufficient bounding of `REP MOVS` to MMIO emulated inside the hypervisor

  - CVE-2014-1666: PHYSDEVOP_{prepare, release}_msix exposed to unprivileged guests");

  script_tag(name:"affected", value:"These vulnerabilities affect all currently supported versions of Citrix XenServer
  up to and including Citrix XenServer 6.2 Service Pack 1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-12-18 17:37:46 +0100 (Thu, 18 Dec 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  exit(0);
}

include("citrix_version_func.inc");
include("host_details.inc");
include("list_array_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( ! hotfixes = get_kb_item("xenserver/patches") )
  exit( 0 );

patches = make_array();

patches['6.2.0'] = make_list( 'XS62ESP1015' );
patches['6.1.0'] = make_list( 'XS61E045' );
patches['6.0.2'] = make_list( 'XS602E038' );
patches['6.0.0'] = make_list( 'XS60E042' );

citrix_xenserver_check_report_is_vulnerable( version:version, hotfixes:hotfixes, patches:patches );

exit( 99 );
