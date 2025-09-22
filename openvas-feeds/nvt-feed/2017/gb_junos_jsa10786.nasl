# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106749");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-13 08:24:49 +0200 (Thu, 13 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)");

  script_cve_id("CVE-2017-2340");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos OS PFE DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected");

  script_tag(name:"summary", value:"Junos OS is prone to a denial of service vulnerability while handling IPv6
ND advertisements.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in processing IPv6 ND packets originating from subscribers
and destined to M/MX series routers configured with Enhanced Subscriber Management for DHCPv6 subscribers can
result in a PFE (Packet Forwarding Engine) hang or crash.

This issue does not affect devices with only IPv4 configured.");

  script_tag(name:"impact", value:"An attacker may cause a denial of service condition.");

  script_tag(name:"affected", value:"Junos OS 15.1 and 16.1");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10786");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^15") {
  if ((revcomp(a: version, b: "15.1R5") < 0) &&
      (revcomp(a: version, b: "15.1R3") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1R5");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^16\.1") {
  if (revcomp(a: version, b: "16.1R3") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.1R3");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
