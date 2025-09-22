# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105917");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-07-17 14:40:26 +0200 (Thu, 17 Jul 2014)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-3822");

  script_name("Juniper Networks Junos OS IPv6 to IPv4 Translating Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected", "juniper/junos/model");

  script_tag(name:"summary", value:"DoS when translating from IPv6 to IPv4.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"A denial of service (DoS) issue has been discovered in Juniper SRX
Series products that can be exploited by remote unauthenticated attackers. This issue takes place when a
certain malformed packet is translated from IPv6 to IPv4. When this malformed packet is sent to a vulnerable
SRX Series device, the flowd process may crash.");

  script_tag(name:"impact", value:"Unauthenticated attackers can cause a DoS condition by repeatedly
exploiting this vulnerability.");

  script_tag(name:"affected", value:"Junos OS 11.4, 12.1, 12.1X44, 12.1X45 and 12.1X46.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As a
workaround disable NAT translation from IPv6 to IPv4 if not required.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10641");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68553");


  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

model = get_kb_item("juniper/junos/model");
if (!model || model !~ "^SRX")
  exit(99);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (revcomp(a:version, b:"11.4R8") < 0) {
  security_message(port:0, data:version);
  exit(0);
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R5") < 0) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X44-D20") < 0) &&
           (revcomp(a:version, b:"12.1X44") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X45-D15") < 0) &&
           (revcomp(a:version, b:"12.1X45") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X46-D10") < 0) &&
           (revcomp(a:version, b:"12.1X46") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X47-D10") < 0) &&
           (revcomp(a:version, b:"12.1X47") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
}
