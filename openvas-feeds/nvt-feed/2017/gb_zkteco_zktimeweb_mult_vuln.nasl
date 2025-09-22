# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zkteco:zktime_web";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140579");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-12-05 12:03:16 +0700 (Tue, 05 Dec 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-20 17:10:00 +0000 (Wed, 20 Dec 2017)");

  script_cve_id("CVE-2017-17056", "CVE-2017-17057");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ZKTeco ZKTime Web Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_zkteco_zktimeweb_detect.nasl");
  script_mandatory_keys("zkteco_zktime/installed");

  script_tag(name:"summary", value:"ZKTeco ZKTime Web is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ZKTeco ZKTime Web is prone to multiple vulnerabilities:

  - Cross-site request forgery vulnerability (CVE-2017-17056)

  - Cross-site scripting vulnerability (CVE-2017-17057)");

  script_tag(name:"affected", value:"ZKTeco ZKTime Web version 2.0.1.12280 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/145159/ZKTeco-ZKTime-Web-2.0.1.12280-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102006");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102007");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/145160/ZKTeco-ZKTime-Web-2.0.1.12280-Cross-Site-Request-Forgery.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.0.1.12280")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
