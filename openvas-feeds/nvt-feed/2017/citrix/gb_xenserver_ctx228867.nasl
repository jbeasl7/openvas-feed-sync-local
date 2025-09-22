# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140421");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-16 09:49:18 +0700 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 10:29:00 +0000 (Tue, 30 Oct 2018)");

  script_cve_id("CVE-2017-15595", "CVE-2017-15588", "CVE-2017-15593", "CVE-2017-15592", "CVE-2017-15594",
                "CVE-2017-15590", "CVE-2017-15589");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix XenServer Multiple Security Updates (CTX228867)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Citrix Xenserver Local Security Checks");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in Citrix
  XenServer that may allow a malicious administrator of a guest VM to compromise the host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:

  - CVE-2017-15595: Unlimited recursion in linear pagetable de-typing

  - CVE-2017-15588: Stale TLB entry due to page type release race

  - CVE-2017-15593: page type reference leak on x86

  - CVE-2017-15592: x86: Incorrect handling of self-linear shadow mappings with translated guests

  - CVE-2017-15594: x86: Incorrect handling of IST settings during CPU hotplug

  - CVE-2017-15590: multiple MSI mapping issues on x86

  - CVE-2017-15589: hypervisor stack leak in x86 I/O intercept code

  For customers that do not have PV-based guests, are not using PCI passthrough and are using hardware with HAP
  support, the risk is reduced to a disclosure of a small part of the hypervisor stack.");

  script_tag(name:"affected", value:"XenServer versions 7.2, 7.1, 7.0, 6.5, 6.2.0, 6.0.2.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX228867");

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

patches['7.2.0'] = make_list('XS72E008');
patches['7.1.0'] = make_list('XS71E016');
patches['7.0.0'] = make_list('XS70E046');
patches['6.5.0'] = make_list('XS65ESP1062');
patches['6.2.0'] = make_list('XS62ESP1065');
patches['6.0.2'] = make_list('XS602ECC049');

citrix_xenserver_check_report_is_vulnerable(version: version, hotfixes: hotfixes, patches: patches);

exit(99);
