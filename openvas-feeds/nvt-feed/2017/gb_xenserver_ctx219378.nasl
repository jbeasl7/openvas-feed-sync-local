# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.1140113");
  script_cve_id("CVE-2016-9932", "CVE-2016-10024", "CVE-2016-10025");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Citrix XenServer Multiple Security Updates (CTX219378)");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX219378");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"Security vulnerabilities have been identified in Citrix XenServer that may allow malicious
  code running within a guest VM to read a small part of hypervisor memory and allow privileged-mode code running within a guest
  VM to hang or crash the host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:

  - CVE-2016-9932 (Low): x86 CMPXCHG8B emulation fails to ignore operand size override

  - CVE-2016-10024 (Medium): x86 PV guests may be able to mask interrupts

  - CVE-2016-10025 (Low): missing NULL pointer check in VMFUNC emulation");

  script_tag(name:"affected", value:"These vulnerabilities affect all currently supported versions of Citrix XenServer up to and including Citrix XenServer 7.0.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-01-03 10:14:13 +0100 (Tue, 03 Jan 2017)");
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

patches['7.0.0'] = make_list( 'XS70E023' );
patches['6.5.0'] = make_list( 'XS65ESP1046' );
patches['6.2.0'] = make_list( 'XS62ESP1054' );
patches['6.0.2'] = make_list( 'XS602ECC039' );

citrix_xenserver_check_report_is_vulnerable( version:version, hotfixes:hotfixes, patches:patches );

exit( 99 );
