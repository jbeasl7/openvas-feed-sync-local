# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106945");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-13 12:42:35 +0700 (Thu, 13 Jul 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-10605");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos OS SRX Series: DHCP DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected", "juniper/junos/model");

  script_tag(name:"summary", value:"Junos OS on SRX series is prone to a denial of service vulnerability in
flowd due to crafted DHCP packet.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"On all vSRX and SRX Series devices, when the DHCP or DHCP relay is
configured, specially crafted packet might cause the flowd process to crash, halting or interrupting traffic
from flowing through the device(s).

Repeated crashes of the flowd process may constitute an extended denial of service condition for the device(s).");

  script_tag(name:"impact", value:"An unauthenticated attacker may cause a denial of service condition.");

  script_tag(name:"affected", value:"Junos OS 12.1X46, 12.3X48 and 15.1X49 on SRX Series.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10789");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

model = get_kb_item("juniper/junos/model");
if (!model || (model !~ '^(V)?SRX'))
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if ((revcomp(a: version, b: "12.1X46-D67") < 0) &&
    (revcomp(a: version, b: "12.1X46") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.1X46-D67");
  security_message(port: 0, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "12.3X48-D55") < 0) &&
    (revcomp(a: version, b: "12.3X48") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.3X48-D55");
  security_message(port: 0, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "15.1X49-D91") < 0) &&
    (revcomp(a: version, b: "15.1X49") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D91");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
