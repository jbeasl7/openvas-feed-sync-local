# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103960");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-12-06 11:10:40 +0700 (Fri, 06 Dec 2013)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2013-4684");

  script_name("Juniper Networks Junos OS PIM Handling DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected", "juniper/junos/build");

  script_tag(name:"summary", value:"Certain PIM packets subject to NAT may cause the Flow Daemon to
crash which can cause a DoS condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"On SRX Series devices where Protocol-Independent Multicast (PIM)
is enabled, certain PIM packets subject to Network Address Translation (NAT) may cause the Flow Daemon
(flowd) to crash. This issue only occurs in a NAT environment and cannot be triggered by PIM packets
sent directly to the SRX.");

  script_tag(name:"impact", value:"A remote attacker can crash the Flow Daemon and by doing this
repeatedly causing a denial of service condition.");

  script_tag(name:"affected", value:"Junos OS 10.4, 11.4, 12.1 and 12.1X44.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10573");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61127");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54157");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("juniper/junos/build");
if (!build)
  exit(0);

desc += "Version/Build-Date:
" + version + " / " + build;

build2check = str_replace(string:build, find:"-", replace:"");

if (revcomp(a:build2check, b:"20130620") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.4R15") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^10\.4S") {
  if (revcomp(a:version, b:"10.4S14") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.4R8") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R7") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.1X44-D15") < 0) &&
             (revcomp(a:version, b:"12.1X") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

exit(99);
