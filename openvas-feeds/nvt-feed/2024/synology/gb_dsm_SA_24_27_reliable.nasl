# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170989");
  script_version("2024-12-17T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-12-17 05:05:41 +0000 (Tue, 17 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-02 08:17:59 +0000 (Mon, 02 Dec 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) Multiple Vulnerabilities (Synology-SA-24:27) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The flaws allows remote attackers to conduct denial of service
  attacks and to obtain sensitive information and remote authenticated users to obtain privileges
  without consent.");

  script_tag(name:"affected", value:"Synology DSM prior to version 7.2.1-69057-2 and 7.2.2 prior to
  7.2.2-72806.");

  script_tag(name:"solution", value:"Update to version 7.2.1-69057-2, 7.2.2-72806 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_24_27");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# TODO: Advisory still says that "Fixed Release Availability" for DSM 7.1 is "Ongoing" so
# this needs to be cross-checked in the future and if fixes are available added here.

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 7.2.1-69057-2 and not 7.2.1-69057), there will be 2 VTs with different qod_type.
if (revcomp(a: version, b: "7.2.1-69057") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1-69057-2");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.2\.2" && (revcomp(a: version, b: "7.2.2-72806") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.2-72806");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.170990
if (version =~ "^7\.2\.1-69057")
  exit(0);

exit(99);
