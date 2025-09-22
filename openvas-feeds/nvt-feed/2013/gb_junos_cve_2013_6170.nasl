# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103949");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-10-28 12:53:03 +0700 (Mon, 28 Oct 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2013-6170");

  script_name("Juniper Networks Junos OS PIM Join Flooding Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected", "juniper/junos/build");

  script_tag(name:"summary", value:"A large number of crafted PIM join messages can crash the RPD
routing daemon.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"Receipt of a large number of crafted IPv4 or IPv6 PIM join
messages in a Next-Generation Multicast VPN (NGEN MVPN) environment can trigger the RPD routing daemon
to crash.");

  script_tag(name:"impact", value:"Once a large amount of these PIM joins are received by the
router, RPD crashes and restarts.");

  script_tag(name:"affected", value:"Junos OS 10.0 or later but only applies to PIM in an NGEN MVPN
environment.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As
a workaround ACLs or firewall filters to limit PIM access to the router only from trusted hosts.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10548");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62973");
  script_xref(name:"URL", value:"http://secunia.com/advisories/55216");

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

if (revcomp(a:build2check, b:"20120927") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.0S28") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^10") {
  if (revcomp(a:version, b:"10.4R7") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.1R5") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"11.2R2") < 0) &&
             (revcomp(a:version, b:"11.2") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"11.4R1") < 0) &&
              revcomp(a:version, b:"11.4") >= 0) {
      security_message(port:0, data:desc);
      exit(0);
  }
}

exit(99);
