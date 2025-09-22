# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gimp:gimp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836166");
  script_version("2025-04-25T05:39:37+0000");
  script_cve_id("CVE-2022-30067");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-04-25 05:39:37 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 00:04:00 +0000 (Thu, 26 May 2022)");
  script_tag(name:"creation_date", value:"2025-04-24 11:30:03 +0530 (Thu, 24 Apr 2025)");
  script_name("GIMP Buffer Overflow Vulnerability (Apr 2025) - Windows");

  script_tag(name:"summary", value:"GIMP is prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct denial of service attacks.");

  script_tag(name:"affected", value:"GIMP version 2.10.30 and 2.99.10 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 2.10.32 or 2.99.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://gitlab.gnome.org/GNOME/gimp/-/issues/8222");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");

  script_dependencies("gb_gimp_detect.nasl");
  script_mandatory_keys("Gimp/Win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"2.10.30") || version_is_equal(version:vers, test_version:"2.99.10")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.10.32 or 2.99.12", install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
