# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106717");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-04 09:13:22 +0700 (Tue, 04 Apr 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ubiquiti Networks Products Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ubnt_discovery_protocol_detect.nasl");
  script_mandatory_keys("ubnt_discovery_proto/detected", "ubnt_discovery_proto/firmware");

  script_tag(name:"summary", value:"Multiple Ubiquiti Networks products are prone to an authenticated command
injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A command injection vulnerability was found in 'pingtest_action.cgi'. The
vulnerability can be exploited by luring an attacked user to click on a crafted link or just surf on a malicious
website. The whole attack can be performed via a single GET-request and is very simple since there is no CSRF
protection.");

  script_tag(name:"solution", value:"Update to the latest firmware.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20170316-0_Ubiquiti_Networks_authenticated_command_injection_v10.txt");
  script_xref(name:"URL", value:"https://community.ubnt.com/t5/airMAX-AC/AirOS-Vulnerability-Issue-Update-3-18-17/m-p/1869507");

  exit(0);
}

include("version_func.inc");

fw = get_kb_item("ubnt_discovery_proto/firmware");

if (!fw || (fw !~ "^(XM|XW|TI|SW|XC|WA)"))
  exit(0);

vers = eregmatch(pattern: "\.v([0-9]\.[0-9]\.[0-9])", string: fw);
if (isnull(vers[1]))
  exit(0);

version = vers[1];

if (fw =~ "^XM|XW|TI") {
  if (version_is_less(version: version, test_version: "6.0.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.0.1");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (fw =~ "^SW") {
  if (version_is_less(version: version, test_version: "1.3.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.3.4");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (fw =~ "^(XC|WA)") {
  if (version_is_less(version: version, test_version: "8.0.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
