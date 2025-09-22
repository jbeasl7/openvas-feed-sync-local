# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103971");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-01-21 09:42:45 +0700 (Tue, 21 Jan 2014)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-0613");

  script_name("Juniper Networks Junos OS DoS Vulnerability in XNM Command Processor");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected", "juniper/junos/build");

  script_tag(name:"summary", value:"Denial of Service vulnerability in XNM command processor.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"When xnm-ssl or xnm-clear-text is enabled within the hierarchy
level of the Junos configuration, an unauthenticated, remote user could exploit the XNM command processor
to consume excessive amounts of memory.");

  script_tag(name:"impact", value:"Remote attackers can cause a denial of service condition on the
device.");

  script_tag(name:"affected", value:"Junos OS 10.4, 11.4, 12.1, 12.2, 12.3, 13.1, 13.2");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10607");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64998");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1029586");

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

if (revcomp(a:build2check, b:"20131217") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.4R16") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.4R10") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R8-S2") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.1X44-D30") < 0) &&
             (revcomp(a:version, b:"12.1X") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.1X45-D20") < 0) &&
             (revcomp(a:version, b:"12.1X45") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.1X46-D10") < 0) &&
             (revcomp(a:version, b:"12.1X46") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.2R7") < 0) &&
             (revcomp(a:version, b:"12.2") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.3R5") < 0) &&
             (revcomp(a:version, b:"12.3") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^13") {
  if (revcomp(a:version, b:"13.1R3-S1") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"13.2R2-S2") < 0) &&
             (revcomp(a:version, b:"13.2") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"13.3R1") < 0) &&
             (revcomp(a:version, b:"13.3") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

exit(99);
