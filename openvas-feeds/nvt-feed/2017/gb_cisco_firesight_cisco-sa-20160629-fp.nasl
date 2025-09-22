# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:firepower_management_center";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106807");
  script_cve_id("CVE-2016-1394");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Cisco Firepower System Software Static Credential Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160629-fp");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in Cisco Firepower System Software could allow an
  unauthenticated, remote attacker to log in to the device with a default account. This account does not have full
  administrator privileges.");

  script_tag(name:"insight", value:"The vulnerability is due to a user account that has a default and static
  password. This account is created during installation. An attacker could exploit this vulnerability by connecting
  either locally or remotely to the affected system.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to log in to the device using
  the default account. The default account allows the execution of a subset of command-line interface (CLI)
  commands that would allow the attacker to partially compromise the device.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 19:58:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2017-05-17 08:51:13 +0700 (Wed, 17 May 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_firepower_management_center_consolidation.nasl");
  script_mandatory_keys("cisco/firepower_management_center/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork: TRUE))
  exit(0);

affected = make_list(
  '6.0.0',
  '6.0.0.1',
  '6.0.1',
  '6.1.0');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
