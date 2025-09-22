# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106941");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-13 09:23:17 +0700 (Thu, 13 Jul 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-2345");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos OS SNMPD RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected");

  script_tag(name:"summary", value:"Junos OS is prone to a remote code execution vulnerability when receiving
a crafted SNMP packet.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"On Junos OS devices with SNMP enabled, a network based attacker with
unfiltered access to the RE can cause the Junos OS snmpd daemon to crash and restart by sending a crafted SNMP
packet. Repeated crashes of the snmpd daemon can result in a partial denial of service condition. Additionally,
it may be possible to craft a malicious SNMP packet in a way that can result in remote code execution.");

  script_tag(name:"impact", value:"An unauthenticated attacker may cause a denial of service condition or
execute arbitrary code.");

  script_tag(name:"affected", value:"Junos OS 10.2 and above.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10793");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (revcomp(a: version, b: "10.2") < 0)
  exit(99);

if (version =~ "^12") {
  if ((revcomp(a: version, b: "12.1X46-D67") < 0) &&
      (revcomp(a: version, b: "12.1X46") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.1X46-D67");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "12.3X48-D51") < 0) &&
           (revcomp(a: version, b: "12.3X48") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.3X48-D51");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^13") {
  if (revcomp(a: version, b: "13.3R10-S2") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.3R10-S2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^14") {
  if ((revcomp(a: version, b: "14.1R9") < 0) &&
      (revcomp(a: version, b: "14.1R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.1R9");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "14.1X53-D44") < 0) &&
           (revcomp(a: version, b: "14.1X53") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.1X53-D44");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "14.2R7-S7") < 0) &&
           (revcomp(a: version, b: "14.2R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.2R7-S7");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^15") {
  if ((revcomp(a: version, b: "15.1F2-S18") < 0) &&
      (revcomp(a: version, b: "15.1F2") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1F2-S18");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1F6-S7") < 0) &&
           (revcomp(a: version, b: "15.1F6") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1F6-S7");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1R7") < 0) &&
           (revcomp(a: version, b: "15.1R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1R7");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X49-D100") < 0) &&
           (revcomp(a: version, b: "15.1X49") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D100");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X53-D47") < 0) &&
           (revcomp(a: version, b: "15.1X53") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X53-D47");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^16") {
  if (revcomp(a: version, b: "16.1R5") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.1R5");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "16.2R2") < 0) &&
           (revcomp(a: version, b: "16.2R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.2R2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^17") {
  if (revcomp(a: version, b: "17.1R2") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "17.1R2");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "17.2R2") < 0) &&
           (revcomp(a: version, b: "17.2R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "17.2R2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
