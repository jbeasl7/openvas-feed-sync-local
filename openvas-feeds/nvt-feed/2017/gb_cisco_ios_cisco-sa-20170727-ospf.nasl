# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106995");
  script_cve_id("CVE-2017-6770");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Cisco IOS Software OSPF LSA Manipulation Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170727-ospf");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Cisco IOS Software is affected by a vulnerability involving the Open Shortest
Path First (OSPF) Routing Protocol Link State Advertisement (LSA) database. This vulnerability could allow an
unauthenticated, remote attacker to take full control of the OSPF Autonomous System (AS) domain routing table,
allowing the attacker to intercept or black-hole traffic.");

  script_tag(name:"insight", value:"The attacker could exploit this vulnerability by injecting crafted OSPF
packets. To exploit this vulnerability, an attacker must accurately determine certain parameters within the LSA
database on the target router. This vulnerability can only be triggered by sending crafted unicast or multicast
OSPF LSA type 1 packets. No other LSA type packets can trigger this vulnerability.

OSPFv3 is not affected by this vulnerability. Fabric Shortest Path First (FSPF) protocol is not affected by this
vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation could cause the targeted router to flush its routing
table and propagate the crafted OSPF LSA type 1 update throughout the OSPF AS domain.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-21 12:53:00 +0000 (Tue, 21 Dec 2021)");
  script_tag(name:"creation_date", value:"2017-07-28 08:38:44 +0700 (Fri, 28 Jul 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list(
  '15.1(2.0)' );

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
