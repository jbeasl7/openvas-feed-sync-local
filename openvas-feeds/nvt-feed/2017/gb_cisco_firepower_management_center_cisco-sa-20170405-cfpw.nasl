# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106719");
  script_cve_id("CVE-2017-3885");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Cisco Firepower Detection Engine SSL Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-cfpw");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the detection engine reassembly of Secure Sockets Layer
  (SSL) packets for Cisco Firepower System Software could allow an unauthenticated, remote attacker to cause a
  denial of service (DoS) condition because the Snort process consumes a high level of CPU resources.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of an SSL packet stream. An
  attacker could exploit this vulnerability by sending a crafted SSL packet stream to the detection engine on the
  targeted device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a DoS condition because the
  Snort process consumes a high level of CPU resources. The device must be manually reloaded to recover from this
  condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-07 09:19:25 +0200 (Fri, 07 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_firepower_management_center_consolidation.nasl");
  script_mandatory_keys("cisco/firepower_management_center/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

affected = make_list(
  '6.0.0',
  '6.1.0',
  '6.2.0',
  '6.2.1');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
