# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806683");
  script_version("2024-02-21T14:36:44+0000");
  script_tag(name:"last_modification", value:"2024-02-21 14:36:44 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-02-12 11:59:34 +0530 (Fri, 12 Feb 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-06 03:06:00 +0000 (Tue, 06 Dec 2016)");

  script_cve_id("CVE-2016-1316");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Video Communications Server Information Disclosure Vulnerability (cisco-sa-20160208-vcs)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_vcs_consolidation.nasl");
  script_mandatory_keys("cisco/vcs/detected");

  script_tag(name:"summary", value:"Cisco Video Communications Server (VCS), when utilized as part
  of a Jabber Guest deployment, contains an information disclosure vulnerability that could allow
  and unauthenticated, remote attacker to gain access to potentially sensitive information.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists due to a failure to properly protect
  an informational URL that contains aggregated call statistics. An attacker that knows the URL
  could submit a request to retrieve the page containing the information.");

  script_tag(name:"affected", value:"Cisco TelePresence Video Communication Server (VCS) version
  X8.1 through X8.7 when used in conjunction with Jabber Guest.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160208-vcs");

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
