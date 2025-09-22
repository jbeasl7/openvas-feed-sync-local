# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106718");
  script_cve_id("CVE-2017-6603");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-14T16:09:27+0000");

  script_name("Cisco ASR 903 and ASR 920 Series Devices IPv6 Packet Processing Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-asr");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in Cisco ASR 903 or ASR 920 Series Devices running with an
RSP2 card could allow an unauthenticated, adjacent attacker to cause a denial of service (DoS) condition on a
targeted system.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient processing of IPv6 packets by the
affected system. The system could push IPv6 traffic to the processor even when the device is not configured for
IPv6, which could cause other control packets to be affected.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause a DoS condition on the
system.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-07 09:09:03 +0200 (Fri, 07 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version", "cisco_ios/model");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (!model = get_kb_item("cisco_ios/model"))
  exit(0);

if (model !~ "^ASR9(0|2)[0-9]$")
  exit(99);

if (version == "15.4(3)S3.15") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
