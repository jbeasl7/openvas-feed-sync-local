# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142673");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2019-07-29 06:24:44 +0000 (Mon, 29 Jul 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-07 02:15:00 +0000 (Sat, 07 Sep 2019)");

  script_cve_id("CVE-2019-13917");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim 4.85 - 4.92 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_exim_smtp_detect.nasl");
  script_mandatory_keys("exim/detected");

  script_tag(name:"summary", value:"Exim is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists if the configuration of Exim uses the ${sort }
  expansion for items that can be controlled by an attacker (e.g. $local_part, $domain). The default
  config, as shipped by the Exim developers, does not contain ${sort }.");

  script_tag(name:"impact", value:"A local or remote attacker can execute programs with root
  privileges - if the Exim server is using an unusual configuration.");

  script_tag(name:"affected", value:"Exim versions 4.85 through 4.92.");

  script_tag(name:"solution", value:"Update to version 4.92.1 or later.");

  script_xref(name:"URL", value:"https://exim.org/static/doc/security/CVE-2019-13917.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.85", test_version2: "4.92")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.92.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
