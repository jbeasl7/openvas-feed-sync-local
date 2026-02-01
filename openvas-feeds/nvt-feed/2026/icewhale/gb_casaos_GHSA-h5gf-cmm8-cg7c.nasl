# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:icewhale:casaos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156133");
  script_version("2026-01-14T05:47:41+0000");
  script_tag(name:"last_modification", value:"2026-01-14 05:47:41 +0000 (Wed, 14 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-13 08:06:32 +0000 (Tue, 13 Jan 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-26 16:48:40 +0000 (Wed, 26 Feb 2025)");

  script_cve_id("CVE-2024-24765");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CasaOS < 0.4.7 Path Traversal Vulnerability - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_casaos_http_detect.nasl");
  script_mandatory_keys("casaos/detected");

  script_tag(name:"summary", value:"CasaOS is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Path filtering of the URL for user avatar image files is not
  strict, making it possible to get any file on the system. This could allow an unauthorized actor
  to access, for example, the CasaOS user database, and possibly obtain system root privileges.");

  script_tag(name:"affected", value:"CasaOS version 0.4.6 and prior.");

  script_tag(name:"solution", value:"Update to version 0.4.7 or later.");

  script_xref(name:"URL", value:"https://github.com/IceWhaleTech/CasaOS-UserService/security/advisories/GHSA-h5gf-cmm8-cg7c");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "0.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.4.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
