# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:my-netdata:netdata";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142518");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-06-28 06:48:04 +0000 (Fri, 28 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-14 11:26:00 +0000 (Wed, 14 Aug 2019)");

  script_cve_id("CVE-2019-9834");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetData <= 1.13.0 HTML Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netdata_detect.nasl");
  script_mandatory_keys("netdata/detected");

  script_tag(name:"summary", value:"NetData is prone to an HTML injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Netdata web application allows remote attackers to inject their own
  malicious HTML code into an imported snapshot, aka HTML Injection.

  Vendor declares that the responsibility rests with the user to import a trusted file. There will be no fix.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker-supplied HTML to run in the context
  of the affected browser, potentially allowing the attacker to steal authentication credentials or to control how
  the site is rendered to the user.");

  script_tag(name:"affected", value:"NetData version 1.13.0 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46545");
  script_xref(name:"URL", value:"https://github.com/netdata/netdata/issues/5800#issuecomment-510986112");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "1.13.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
