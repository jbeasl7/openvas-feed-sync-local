# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141884");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-17 13:02:49 +0700 (Thu, 17 Jan 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-6441");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Coship Wireless Router Password Reset Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_coship_router_snmp_detect.nasl");
  script_mandatory_keys("coship_router/detected");

  script_tag(name:"summary", value:"Coship Wireless Routers are prone to an unauthenticated admin password
  reset.");

  script_tag(name:"affected", value:"Coship RT3052 - 4.0.0.48, Coship RT3050 - 4.0.0.40, Coship WM3300 - 5.0.0.54,
  Coship WM3300 - 5.0.0.55, Coship RT7620 - 10.0.0.49 and probably prior versions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/151202/Coship-Wireless-Router-Unauthenticated-Admin-Password-Reset.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/h:coship:rt3052",
                     "cpe:/h:coship:rt3050",
                     "cpe:/h:coship:wm3300",
                     "cpe:/h:coship:rt7620");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe  = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/h:coship:rt3052") {
  if (version_is_less_equal(version: version, test_version: "4.0.0.48")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:coship:rt3050") {
  if (version_is_less_equal(version: version, test_version: "4.0.0.40")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:coship:wm3300") {
  if (version_is_less_equal(version: version, test_version: "5.0.0.55")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:coship:rt7620") {
  if (version_is_less_equal(version: version, test_version: "10.0.0.49")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
