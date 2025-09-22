# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gnome:libsoup";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140320");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-08-22 11:08:37 +0700 (Tue, 22 Aug 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 17:25:00 +0000 (Tue, 07 Jun 2022)");

  script_cve_id("CVE-2017-2885");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("libsoup RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_libsoup_detect.nasl");
  script_mandatory_keys("libsoup/detected");

  script_tag(name:"summary", value:"An exploitable stack based buffer overflow vulnerability exists
  in the GNOME libsoup. A specially crafted HTTP request can cause a stack overflow resulting in
  remote code execution (RCE). An attacker can send a special HTTP request to the vulnerable server
  to trigger this vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"libsoup version 2.59.90 and prior.");

  script_tag(name:"solution", value:"Update to version 2.59.90.1 or later");

  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0392");
  script_xref(name:"URL", value:"http://ftp.gnome.org/pub/GNOME/sources/libsoup/2.59/libsoup-2.59.90.1.news");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.59.90")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.59.90.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
