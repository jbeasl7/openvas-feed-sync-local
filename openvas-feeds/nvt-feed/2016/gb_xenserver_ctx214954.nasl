# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105833");
  script_cve_id("CVE-2016-6258", "CVE-2016-6259");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Citrix XenServer Multiple Security Updates (CTX214954)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX214954");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in
  Citrix XenServer that may allow a malicious administrator of a PV guest VM to compromise or crash the host.");

  script_tag(name:"affected", value:"These vulnerabilities affect all currently supported versions of Citrix
  XenServer up to and including Citrix XenServer 7.0.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-07-28 18:00:20 +0200 (Thu, 28 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

patches['7.0.0'] = make_list( 'XS70E008' );
patches['6.5.0'] = make_list( 'XS65ESP1034' );
patches['6.2.0'] = make_list( 'XS62ESP1045' );
patches['6.1.0'] = make_list( 'XS61E071' );
patches['6.0.2'] = make_list( 'XS602E052', 'XS602ECC033' );
patches['6.0.0'] = make_list( 'XS60E062' );

citrix_xenserver_check_report_is_vulnerable( version:version, hotfixes:hotfixes, patches:patches );

exit( 99 );
