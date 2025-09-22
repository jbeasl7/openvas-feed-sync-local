# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106915");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-30 16:20:13 +0700 (Fri, 30 Jun 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-10911", "CVE-2017-10912", "CVE-2017-10913", "CVE-2017-10914", "CVE-2017-10915",
                "CVE-2017-10917", "CVE-2017-10918", "CVE-2017-10920", "CVE-2017-10921", "CVE-2017-10922");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix XenServer Multiple Security Updates (CTX224740)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Citrix Xenserver Local Security Checks");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  script_tag(name:"summary", value:"A number of security issues have been identified within Citrix XenServer.");

  script_tag(name:"impact", value:"These issues could, if exploited, allow a malicious administrator of a guest VM
  to compromise the host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:

  - CVE-2017-10920, CVE-2017-10921, CVE-2017-10922 (High): Grant table operations mishandle reference counts.

  - CVE-2017-10918 (High): Stale P1M mappings due to insufficient error checking.

  - CVE-2017-10912 (Medium): Page transfer may allow PV guest to elevate privilege.

  - CVE-2017-10913, CVE-2017-10914 (Medium): Races in the grant table unmap code.

  - CVE-2017-10915 (Medium): x85: insufficient reference counts during shadow emulation.

  - CVE-2017-10917 (Medium): NULL pointer deref in event channel poll.

  - CVE-2017-10911 (Low): blkif responses leak backend stack data.");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_tag(name:"affected", value:"XenServer versions 7.2, 7.1, 7.0, 6.5, 6.2.0, 6.0.2.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX224740");

  exit(0);
}

include("citrix_version_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("misc_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (!hotfixes = get_kb_item("xenserver/patches"))
  exit(0);

patches = make_array();

patches['7.2.0'] = make_list('XS72E001', 'XS72E002');
patches['7.1.0'] = make_list('XS71E011', 'XS71E012');
patches['7.0.0'] = make_list('XS70E035', 'XS70E036');
patches['6.5.0'] = make_list('XS65ESP1057', 'XS65ESP1058');
patches['6.2.0'] = make_list('XS62ESP1061', 'XS62ESP1062');
patches['6.0.2'] = make_list('XS602ECC045', 'XS602ECC046');

citrix_xenserver_check_report_is_vulnerable(version: version, hotfixes: hotfixes, patches: patches);

exit(99);
