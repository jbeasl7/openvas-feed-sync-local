# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106950");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-13 15:37:21 +0700 (Thu, 13 Jul 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-26 13:19:00 +0000 (Thu, 26 May 2016)");

  script_cve_id("CVE-2016-1887");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos OS DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected");

  script_tag(name:"summary", value:"Junos OS is prone to a denial of service vulnerability in sendmsg().");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"Incorrect argument handling in the socket code allows a malicious local
user to overwrite large portions of the kernel memory, and in doing so may be able to take control of the system
or crash the system.");

  script_tag(name:"affected", value:"Junos OS 14.1X53, 14.2, 15.1, 15.1X49, 15.1X53.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10797");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^14") {
  if ((revcomp(a: version, b: "14.1X53-D40") < 0) &&
      (revcomp(a: version, b: "14.1X53") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.1X53-D40");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "14.2R7") < 0) &&
           (revcomp(a: version, b: "14.2R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.2R7");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^15") {
  if ((revcomp(a: version, b: "15.1F7") < 0) &&
      (revcomp(a: version, b: "15.1F") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1F7");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1R5") < 0) &&
           (revcomp(a: version, b: "15.1R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1R5");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X49-D60") < 0) &&
           (revcomp(a: version, b: "15.1X49") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D60");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X53-D60") < 0) &&
           (revcomp(a: version, b: "15.1X53") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X53-D60");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
