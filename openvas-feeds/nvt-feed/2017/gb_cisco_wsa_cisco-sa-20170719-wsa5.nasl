# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106975");
  script_cve_id("CVE-2017-6751");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Cisco Web Security Appliance Administrative Interface Access Control Bypass Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170719-wsa5");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the web proxy functionality of the Cisco Web Security
Appliance (WSA) could allow an unauthenticated, remote attacker to forward traffic from the web proxy interface of
an affected device to the administrative management interface of an affected device.");

  script_tag(name:"insight", value:"The vulnerability exists because the affected software fails to deny traffic
that is forwarded from the web proxy interface to the administrative management interface of a device. An attacker
could exploit this vulnerability by sending a crafted stream of HTTP or HTTPS traffic to the web proxy interface
of an affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow traffic to reach the administrative
management interface of the affected device although the traffic should have been dropped.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-05 17:57:00 +0000 (Mon, 05 Apr 2021)");
  script_tag(name:"creation_date", value:"2017-07-20 14:47:44 +0700 (Thu, 20 Jul 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

affected = make_list(
  '10.0.0-232',
  '10.0.0-233',
  '10.1.0-204',
  '9.0.0-162',
  '9.0.0-193',
  '9.0.0-485');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

