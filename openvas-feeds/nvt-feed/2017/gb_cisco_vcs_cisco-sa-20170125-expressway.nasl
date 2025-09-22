# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106544");
  script_version("2024-02-21T14:36:44+0000");
  script_tag(name:"last_modification", value:"2024-02-21 14:36:44 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-01-26 11:29:25 +0700 (Thu, 26 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-3790");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco TelePresence VCS Denial of Service Vulnerability (cisco-sa-20170125-expressway)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_vcs_consolidation.nasl");
  script_mandatory_keys("cisco/vcs/detected");

  script_tag(name:"summary", value:"A vulnerability in the received packet parser of Cisco
  TelePresence Video Communication Server (VCS) software could allow an unauthenticated, remote
  attacker to cause a reload of the affected system, resulting in a denial of service (DoS)
  condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient size validation of
  user-supplied data. An attacker could exploit this vulnerability by sending crafted H.224 data in
  Real-Time Transport Protocol (RTP) packets in an H.323 call.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to overflow a buffer in a
  cache that belongs to the received packet parser, which will result in a crash of the
  application, resulting in a DoS condition.");

  script_tag(name:"solution", value:"Update to version X8.8.2 or later.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170125-expressway");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "8.8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.8.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
