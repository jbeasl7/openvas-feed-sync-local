# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170262");
  script_version("2024-03-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2024-03-15 05:06:15 +0000 (Fri, 15 Mar 2024)");
  script_tag(name:"creation_date", value:"2022-12-05 14:15:32 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-25 17:26:00 +0000 (Fri, 25 Feb 2022)");

  script_cve_id("CVE-2016-2124", "CVE-2020-25717");

  # nb: Seems that the affected component needs to be update separately
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager (SRM) Multiple Samba Vulnerabilities (Synology-SA-21:29)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities in Samba.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-2124: SMB1 improper authentication

  - CVE-2020-25717: Privilege escalation due to a flaw in the way Samba maps domain users to
  local users");

  script_tag(name:"affected", value:"SRM version 1.2.x.");

  script_tag(name:"solution", value:"- Update SMB Service to version 4.15.13-0781 or later

  - Update Synology Directory Server to version 4.15.13-0615 or later

  Please see the referenced vendor advisory for further information.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_21_29");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: Advisory only marks SRM 1.2 as affected
if (version =~ "^1\.2") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
