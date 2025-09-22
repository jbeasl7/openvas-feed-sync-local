# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140127");
  script_cve_id("CVE-2017-5572", "CVE-2017-5573", "CVE-2015-5300", "CVE-2015-7704", "CVE-2015-7705");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Citrix XenServer Multiple Security Updates (CTX220112)");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX220112");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"Several security issues have been identified within Citrix XenServer.");

  script_tag(name:"impact", value:"These issues could, if exploited, allow an authenticated administrator to
  perform a denial-of-service attack against the host, even when that administrator has a less-privileged RBAC role
  (e.g. read-only). In addition, the issues could permit an attacker with the ability to influence NTP traffic on
  the management network to disrupt time synchronization on the host until the next reboot.");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:

  - CVE-2017-5572 (Low): Authenticated read-only administrator can corrupt host database

  - CVE-2017-5573 (Low): Authenticated read-only administrator can cancel tasks of other administrators

  - CVE-2015-5300, CVE-2015-7704, CVE-2015-7705 (Low): NTP updates.

  Customers who have not enabled NTP are unaffected by the NTP issues.

  Customers who have not enabled RBAC are unaffected by the RBAC issues.

  Customers using Citrix XenServer 6.0.2 in the Common Criteria configuration are unaffected by the RBAC issues.");

  script_tag(name:"affected", value:"XenServer 7.0

  XenServer 6.5

  XenServer 6.2.0

  XenServer 6.0.2");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 13:15:00 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"creation_date", value:"2017-01-26 10:36:18 +0100 (Thu, 26 Jan 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

patches['7.0.0'] = make_list( 'XS70E018',    'XS70E025' );
patches['6.5.0'] = make_list( 'XS65ESP1040', 'XS65ESP1047' );
patches['6.2.0'] = make_list( 'XS62ESP1051', 'XS62ESP1055' );
patches['6.0.2'] = make_list( 'XS602ECC036' );

citrix_xenserver_check_report_is_vulnerable( version:version, hotfixes:hotfixes, patches:patches );

exit( 99 );
