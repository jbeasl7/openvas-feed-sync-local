# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:cisco:rv";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105847");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-08-05 15:24:41 +0200 (Fri, 05 Aug 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_cve_id("CVE-2015-6397");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco RV110W, RV130W, and RV215W Routers Static Credential Vulnerability (cisco-sa-20160803-rv110_130w2)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_small_business_devices_consolidation.nasl");
  script_mandatory_keys("cisco/small_business/detected");

  script_tag(name:"summary", value:"A vulnerability in the default account when used with a
  specific configuration of the Cisco RV110W Wireless-N VPN Firewall, Cisco RV130W Wireless-N
  Multifunction VPN Router, and the Cisco RV215W Wireless-N VPN Router could allow an
  authenticated, remote attacker to gain root access to the device. The account could incorrectly
  be granted root privileges at authentication time.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"This vulnerability is fixed in the following firmware versions:

  - RV110W Wireless-N VPN Firewall, Release 1.2.1.7

  - RV130W Wireless-N Multifunction VPN Router, Release 1.0.3.16

  - RV215W Wireless-N VPN Router, Release 1.3.0.8");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160803-rv110_130w2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (cpe !~ "^cpe:/o:cisco:rv[12]")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:cisco:rv110w_firmware") {
  if (version_in_range(version: version, test_version: "1.2.1", test_version2: "1.2.1.6"))
    fix = "1.2.1.7";
}

if (cpe == "cpe:/o:cisco:rv130w_firmware") {
  if (version_in_range(version: version, test_version: "1.0.3", test_version2: "1.0.3.15"))
    fix = "1.0.3.16";
}

if (cpe == "cpe:/o:cisco:rv215w_firmware") {
  if (version_in_range(version: version, test_version: "1.3.0", test_version2: "1.3.0.7"))
    fix = "1.3.0.8";
}

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
