# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atheme:atheme";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106634");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-07 08:12:26 +0700 (Tue, 07 Mar 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-6384");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atheme IRC DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_atheme_detect.nasl");
  script_mandatory_keys("atheme/installed");

  script_tag(name:"summary", value:"Atheme is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Memory leak in the login_user function in saslserv/main.c in
  saslserv/main.so allows a remote unauthenticated attacker to consume memory and cause a denial of service.");

  script_tag(name:"affected", value:"Atheme version 7.2.7.");

  script_tag(name:"solution", value:"Update to version 7.2.8 or later.");

  script_xref(name:"URL", value:"https://github.com/atheme/atheme/releases/tag/v7.2.8");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96552");
  script_xref(name:"URL", value:"https://github.com/atheme/atheme/pull/539");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version == "7.2.7") {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.8");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
