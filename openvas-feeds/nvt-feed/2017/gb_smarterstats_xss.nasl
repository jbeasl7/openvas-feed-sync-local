# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:smartertools:smarterstats";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107190");
  script_version("2024-03-04T05:10:24+0000");
  script_cve_id("CVE-2017-14620");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"last_modification", value:"2024-03-04 05:10:24 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-11 13:16:00 +0000 (Wed, 11 Oct 2017)");
  script_tag(name:"creation_date", value:"2017-10-18 10:31:53 +0200 (Wed, 18 Oct 2017)");

  script_name("SmarterStats < 11.3.6480 XSS Vulnerability");

  script_tag(name:"summary", value:"SmarterStats is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to rendering the Referer Field in IIS Logfiles and possibly other Field Names. This causes a stored DOM Xss attack.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to execute arbitrary script code in the context of a trusted user.");

  script_tag(name:"affected", value:"SmarterStats 11.3.6347 and previous versions.");

  script_tag(name:"solution", value:"Update to 11.3.6480.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42923/");
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_smarterstats_detect.nasl");
  script_mandatory_keys("smarterstats/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!ver = get_app_version(cpe: CPE, port: port))
  exit(0);

if( version_is_less(version:ver, test_version:"11.3.6480") ) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"11.3.6480");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
