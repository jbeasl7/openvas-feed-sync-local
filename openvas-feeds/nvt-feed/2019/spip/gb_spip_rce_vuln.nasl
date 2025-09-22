# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:spip:spip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142267");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-04-16 09:13:24 +0000 (Tue, 16 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 18:15:00 +0000 (Mon, 28 Sep 2020)");

  script_cve_id("CVE-2019-11071");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SPIP 3.1.x/3.2.x Authenticated RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_spip_http_detect.nasl");
  script_mandatory_keys("spip/detected");

  script_tag(name:"summary", value:"SPIP allows authenticated visitors to execute arbitrary code on the host
  server because var_memotri is mishandled.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"SPIP 3.1.0 - 3.1.9 and 3.2.0 - 3.2.3.");

  script_tag(name:"solution", value:"Update to version 3.1.10, 3.2.4 or later.");

  script_xref(name:"URL", value:"https://blog.spip.net/Mise-a-jour-CRITIQUE-de-securite-Sortie-de-SPIP-3-1-10-et-SPIP-3-2-4.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_in_range(version: version, test_version: "3.1", test_version2: "3.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.10", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.2", test_version2: "3.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.4", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
