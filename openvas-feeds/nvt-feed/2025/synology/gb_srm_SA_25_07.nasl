# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128142");
  script_version("2025-06-13T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-06-13 05:40:07 +0000 (Fri, 13 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-06 15:48:05 +0000 (Fri, 06 Jun 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2025-5293");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Synology Router Manager (SRM) 1.3.x File Write Vulnerability (Synology-SA-25:07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to a file write
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability allows remote authenticated users to write to
  limited files via Server Message Block (SMB) service.");

  script_tag(name:"affected", value:"SRM version 1.3.x.");

  script_tag(name:"solution", value:"No known solution is available as of 12th June, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_25_07");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb:
# - The advisory describes the CVE as "Reserved", and the details of the vulnerability will be
#   provided in a future advisory
# - Once a solution is available it needs to be checked if this needs to be split into two VTs
#   similar to other existing ones
if (version =~ "^1\.3") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
