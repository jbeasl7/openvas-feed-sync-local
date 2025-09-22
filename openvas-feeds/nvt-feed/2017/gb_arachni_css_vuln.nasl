# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:arachni:arachni";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107221");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-15 12:26:25 +0200 (Thu, 15 Jun 2017)");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Arachni v1.5-0.5.11 - Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Arachni is vulnerable to a Cross-Site Scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The target URL field which is available when configuring a scan is
  vulnerable to cross site scripting. As scans can be shared and viewed by other users including the
  admin account, it is possible to execute the cross-site scripting under another users context.");

  script_tag(name:"impact", value:"The vulnerability allows remote attackers to inject own malicious
  script codes on the application-side of the vulnerable service.");

  script_tag(name:"affected", value:"Arachni Version 1.5-0.5.11.");

  script_tag(name:"solution", value:"Update to 1.5-0.5.12 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/May/5");
  script_xref(name:"URL", value:"https://github.com/Arachni/arachni-ui-web/blob/experimental/CHANGELOG.md#0512-march-29-2017");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_arachni_detect.nasl");
  script_mandatory_keys("arachni/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!ver = get_app_version(cpe: CPE, port: port))
  exit(0);

if(!webui_ver = get_kb_item("arachni/webui"))
  exit(0);

if(version_is_equal(version: ver, test_version: "1.5") &&
   version_is_less(version: webui_ver, test_version: "0.5.12")) {
  report = report_fixed_ver(installed_version: ver, fixed_version: "1.5-0.5.12");
  security_message(data: report, port: port);
  exit(0);
}

exit (99);
