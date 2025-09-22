# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809771");
  script_version("2024-02-21T14:36:44+0000");
  script_tag(name:"last_modification", value:"2024-02-21 14:36:44 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-12-23 16:17:36 +0530 (Fri, 23 Dec 2016)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-22 21:11:00 +0000 (Thu, 22 Dec 2016)");

  script_cve_id("CVE-2016-9207");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Video Communications Server Security Bypass Vulnerability (cisco-sa-20161207-expressway)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_vcs_consolidation.nasl");
  script_mandatory_keys("cisco/vcs/detected");

  script_tag(name:"summary", value:"A vulnerability in the HTTP traffic server component of Cisco
  Expressway could allow an unauthenticated, remote attacker to initiate TCP connections to
  arbitrary hosts. This does not allow for full traffic proxy through the Expressway.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient access control for TCP
  traffic passed through the Cisco Expressway. An attacker could exploit this vulnerability by
  sending a crafted URL through the Cisco Expressway.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to enumerate hosts and
  services of arbitrary hosts, as well as degrade performance through the Cisco Expressway.");

  script_tag(name:"affected", value:"Cisco TelePresence Video Communication Server (VCS) version
  X8.7.2 and X8.8.3.");

  script_tag(name:"solution", value:"Upgrade to version X8.9 or later.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-expressway");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_equal(version: version, test_version: "8.7.2") ||
    version_is_equal(version: version, test_version: "8.8.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
