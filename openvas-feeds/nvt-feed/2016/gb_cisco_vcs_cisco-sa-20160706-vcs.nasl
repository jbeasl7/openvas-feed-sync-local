# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107025");
  script_version("2024-02-21T14:36:44+0000");
  script_tag(name:"last_modification", value:"2024-02-21 14:36:44 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-07-11 16:46:52 +0200 (Mon, 11 Jul 2016)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-27 18:33:00 +0000 (Thu, 27 Aug 2020)");

  script_cve_id("CVE-2016-1444");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Video Communication Server Trusted Certificate Authentication Bypass Vulnerability (cisco-sa-20160706-vcs)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_vcs_consolidation.nasl");
  script_mandatory_keys("cisco/vcs/detected");

  script_tag(name:"summary", value:"A vulnerability in certificate management and validation for
  the Mobile and Remote Access (MRA) feature for Cisco TelePresence Video Communication Server
  (VCS) could allow an unauthenticated, remote attacker to bypass authentication and access
  internal HTTP system resources.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to lack of proper input validation of
  a trusted certificate. An attacker could exploit this vulnerability by connecting to the targeted
  device with a trusted certificate.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to bypass authentication and
  access internal HTTP system resources.");

  script_tag(name:"affected", value:"Cisco TelePresence Video Communication Server (VCS) X8.1
  through X8.7.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160706-vcs");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "8.1", test_version2: "8.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
