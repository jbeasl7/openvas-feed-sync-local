# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106777");
  script_cve_id("CVE-2017-3860", "CVE-2017-3861", "CVE-2017-3862", "CVE-2017-3863");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco IOS XE Software EnergyWise Denial of Service Vulnerabilities");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-energywise");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Multiple vulnerabilities in the EnergyWise module of Cisco IOS XE Software
could allow an unauthenticated, remote attacker to cause a buffer overflow condition or a reload of an affected
device, leading to a denial of service (DoS) condition.");

  script_tag(name:"insight", value:"An exploit could allow the attacker to cause a buffer overflow condition or a
reload of the affected device, leading to a DoS condition.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a buffer overflow condition or
a reload of the affected device, leading to a DoS condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-04-20 15:41:40 +0200 (Thu, 20 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

affected = make_list(
  '3.18.1SP',
  '3.2.1SG',
  '3.2.8SG',
  '3.3.1SG',
  '3.3.1SQ',
  '3.4.1SG',
  '3.4.2SG',
  '3.4.3SG',
  '3.4.6SG',
  '3.4.8SG',
  '3.5.1E',
  '3.5.3E',
  '3.6.0E',
  '3.6.1E',
  '3.6.2E',
  '3.6.2a.E',
  '3.6.4E',
  '3.6.5E',
  '3.6.5a.E',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.8.0E');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
