# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_mcu_mse_series_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106543");
  script_cve_id("CVE-2017-3792");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2025-09-09T14:09:45+0000");

  script_name("Cisco TelePresence Multipoint Control Unit Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170125-telepresence");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in a proprietary device driver in the kernel of Cisco
TelePresence Multipoint Control Unit (MCU) Software could allow an unauthenticated, remote attacker to execute
arbitrary code or cause a denial of service (DoS) condition.");

  script_tag(name:"insight", value:"The vulnerability is due to improper size validation when reassembling
fragmented IPv4 or IPv6 packets. An attacker could exploit this vulnerability by sending crafted IPv4 or IPv6
fragments to a port receiving content in Passthrough content mode.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to overflow a buffer. If successful, the
attacker could execute arbitrary code or cause a DoS condition on the affected system.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-26 01:29:00 +0000 (Wed, 26 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-01-26 11:29:25 +0700 (Thu, 26 Jan 2017)");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_telepresence_snmp_detect.nasl", "gb_cisco_telepresence_ftp_detect.nasl");
  script_mandatory_keys("cisco/telepresence/version", "cisco/telepresence/typ");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

typ = get_kb_item("cisco/telepresence/typ");
if (!typ || "MCU" >!< typ)
  exit(0);

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list( '4.3(1.68)',
                      '4.3(2.18)',
                      '4.3(2.30)',
                      '4.3(2.32)',
                      '4.4(3.42)',
                      '4.4(3.49)',
                      '4.4(3.54)',
                      '4.4(3.57)',
                      '4.4(3.67)',
                      '4.5(1.45)',
                      '4.5(1.55)',
                      '4.5(1.85)',
                      '4.5(1.72)',
                      '4.5(1.71)' );

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

