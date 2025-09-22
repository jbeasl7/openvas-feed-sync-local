# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105145");
  script_cve_id("CVE-2014-4021", "CVE-2014-4947", "CVE-2014-4948");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-27T05:05:09+0000");

  script_name("Citrix XenServer Multiple Security Updates (CTX140984)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX140984");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68070");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68659");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68660");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in Citrix XenServer.
  These vulnerabilities affect all currently supported versions of Citrix XenServer up to and including Citrix
  XenServer 6.2 Service Pack 1.");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:

  - CVE-2014-4021: Citrix XenServer potential guest information leak through hypervisor page reuse

  - CVE-2014-4947: Buffer overflow in Citrix XenServer HVM graphics console support

  - CVE-2014-4948: Citrix XenServer guest denial of service and information leak through guest VHD modification");

  script_tag(name:"affected", value:"Citrix XenServer 6.2 Service Pack 1

  Citrix XenServer 6.1

  Citrix XenServer 6.0.2

  Citrix XenServer 6.0.0");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
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

patches['6.2.0'] = make_list( 'XS62ESP1008' );
patches['6.1.0'] = make_list( 'XS61E041', 'XS61E040' );
patches['6.0.2'] = make_list( 'XS602E035','XS602ECC011', 'XS602ECC010' );
patches['6.0.0'] = make_list( 'XS60E039', 'XS60E038' );

citrix_xenserver_check_report_is_vulnerable( version:version, hotfixes:hotfixes, patches:patches );

exit( 99 );
