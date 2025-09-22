# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:inedo:proget";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141541");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-10-01 16:20:09 +0700 (Mon, 01 Oct 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-23 13:08:00 +0000 (Fri, 23 Nov 2018)");

  script_cve_id("CVE-2017-15608");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Inedo ProGet < 5.0.4 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_inedo_proget_detect.nasl");
  script_mandatory_keys("inedo_proget/detected");

  script_tag(name:"summary", value:"Inedo ProGet is prone to a CSRF vulnerability allowing an attacker to change
advanced settings.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ProGet versions prior to 5.0.4");

  script_tag(name:"solution", value:"Update to version 5.0.4 or later.");

  script_xref(name:"URL", value:"https://inedo.com/blog/proget-50-beta5-released");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
