# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105914");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-07-17 14:33:08 +0200 (Thu, 17 Jul 2014)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-3815");

  script_name("Juniper Networks Junos OS SIP ALG Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected", "juniper/junos/model");

  script_tag(name:"summary", value:"DoS on SRX devices when SIP ALG is enabled");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"On SRX Series devices, when SIP ALG is enabled, a certain crafted
SIP packet may cause the flowd process to crash. SIP ALG is enabled by default on SRX Series devices except
for SRX-HE devices. SRX-HE devices have SIP ALG disabled by default. The status of ALGs can beobtained by
executing the 'show security alg status' CLI command.");

  script_tag(name:"impact", value:"Repeated crashes of the flowd process constitutes an extended
denial of service condition for the SRX Series device.");

  script_tag(name:"affected", value:"Junos OS 12.1X46 and 12.1X47");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As a
workaround disable SIP ALG or enable flow-based processing for IPv6 traffic.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10633");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68551");


  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

model = get_kb_item("juniper/junos/model");
if (!model || model !~ "^SRX")
  exit(99);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^12\.1X") {
  if ((revcomp(a:version, b:"12.1X46-D20") < 0) &&
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
