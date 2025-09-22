# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:meeting_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106596");
  script_cve_id("CVE-2017-3837");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Cisco Meeting Server HTTP Packet Processing Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170215-cms1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Web Bridge interface of the Cisco Meeting Server
(CMS), formerly Acano Conferencing Server, could allow an authenticated, remote attacker to retrieve memory
contents, which could lead to the disclosure of confidential information. In addition, the attacker could
potentially cause the application to crash unexpectedly, resulting in a denial of service (DoS) condition. The
attacker would need to be authenticated and have a valid session with the Web Bridge.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of an HTTP request.
An attacker could exploit this vulnerability by sending a crafted HTTP packet to a targeted application.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to retrieve memory contents,
which could lead to the disclosure of confidential information or cause a DoS condition.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-25 01:29:00 +0000 (Tue, 25 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-02-16 12:05:59 +0700 (Thu, 16 Feb 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_meeting_server_snmp_detect.nasl");
  script_mandatory_keys("cisco/meeting_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list(
                '2.0.0',
                '2.0.1',
                '2.0.3',
                '2.0.4',
                '2.0.5',
                '2.0.6',
                '2.0.7',
                '2.0.8',
                '2.0.9',
                '2.1.0',
                '2.1.1' );

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.1.2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

