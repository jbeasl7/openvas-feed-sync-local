# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:swiftmailer:swiftmailer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809773");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2016-10074");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");
  script_tag(name:"creation_date", value:"2016-12-29 19:37:23 +0530 (Thu, 29 Dec 2016)");
  script_name("SwiftMailer RCE Vulnerability");

  script_tag(name:"summary", value:"SwiftMailer is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to: PHPMailer uses the
  Sender variable to build the params string. The validation is done using the
  RFC 3696 specification, which can allow emails to contain spaces when it has
  double quote.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows an
  remote attacker to execute arbitrary code in the context of the web server and
  compromise the target web application.");

  script_tag(name:"affected", value:"SwiftMailer prior to version 5.4.5.");

  script_tag(name:"solution", value:"Upgrade to SwiftMailer version 5.4.5 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/774");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95140");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40972");
  script_xref(name:"URL", value:"https://legalhackers.com/advisories/SwiftMailer-Exploit-Remote-Code-Exec-CVE-2016-10074-Vuln.html");
  script_xref(name:"URL", value:"https://github.com/swiftmailer/swiftmailer/releases/tag/v5.4.5");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_swiftmailer_detect.nasl");
  script_mandatory_keys("swiftmailer/Installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"5.4.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"5.4.5");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
