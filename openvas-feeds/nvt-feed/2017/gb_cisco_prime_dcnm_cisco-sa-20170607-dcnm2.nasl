# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_data_center_network_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106852");
  script_cve_id("CVE-2017-6640");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Prime Data Center Network Manager Server Static Credential Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-dcnm2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to Cisco Prime DCNM Software releases 10.2(1) or later.");

  script_tag(name:"summary", value:"A vulnerability in Cisco Prime Data Center Network Manager (DCNM) Software
could allow an unauthenticated, remote attacker to log in to the administrative console of a DCNM server by using
an account that has a default, static password. The account could be granted root- or system-level privileges.");

  script_tag(name:"insight", value:"The vulnerability exists because the affected software has a default user
account that has a default, static password. The user account is created automatically when the software is
installed. An attacker could exploit this vulnerability by connecting remotely to an affected system and logging
in to the affected software by using the credentials for this default user account.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to use this default user
account to log in to the affected software and gain access to the administrative console of a DCNM server.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-06-08 10:09:07 +0700 (Thu, 08 Jun 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_prime_data_center_network_manager_detect.nasl");
  script_mandatory_keys("cisco_prime_dcnm/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list('10.1.0',
                     '10.1(1)',
                     '10.1(2)');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "10.2(1)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
