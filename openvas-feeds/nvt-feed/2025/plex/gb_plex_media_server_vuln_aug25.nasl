# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:plex:plex_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155198");
  script_version("2025-08-22T15:40:55+0000");
  script_tag(name:"last_modification", value:"2025-08-22 15:40:55 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-22 03:54:47 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-34158");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plex Media Server 1.41.7.x - 1.42.0.x Undisclosed Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_plex_media_server_http_detect.nasl");
  script_mandatory_keys("plex_media_server/detected");

  script_tag(name:"summary", value:"Plex Media Server is prone to an undisclosed vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Plex Media Server (PMS) is affected by an unspecified security
  vulnerability reported via Plex's bug bounty program. While technical details have not been
  publicly disclosed, the issue was acknowledged by the vendor. The vulnerability may pose a risk
  to system integrity, confidentiality, or availability, prompting a strong recommendation for all
  users to upgrade immediately.");

  script_tag(name:"affected", value:"Plex Media Server version 1.41.7.x through 1.42.0.x.");

  script_tag(name:"solution", value:"Update to version 1.42.1 or later.");

  script_xref(name:"URL", value:"https://forums.plex.tv/t/plex-media-server-security-update/928341");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive( version: version, test_version_lo: "1.41.7", test_version_up: "1.42.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.42.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
