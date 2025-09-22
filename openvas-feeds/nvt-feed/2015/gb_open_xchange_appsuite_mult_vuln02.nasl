# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806070");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-5236", "CVE-2014-5237");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-06 19:54:00 +0000 (Thu, 06 Feb 2020)");
  script_tag(name:"creation_date", value:"2015-10-05 16:02:56 +0530 (Mon, 05 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) App Suite Multiple Vulnerabilities -02 (Oct 2015)");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Crafted OLE Objects within OpenDocument Text files can be used to reference
    objects with absolute or relative paths.

  - Server-side request forgery (SSRF) vulnerability in the documentconverter
    component in Open-Xchange (OX) AppSuite");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to access or read arbitrary files that contain sensitive information, to
  perform certain unauthorized actions and gain access to the affected
  application. Other attacks are also possible.");

  script_tag(name:"affected", value:"Open-Xchange (OX) App Suite versions before
  7.4.2-rev10 and 7.6.x before 7.6.0-rev10.");

  script_tag(name:"solution", value:"Update to version 7.4.2-rev10 or 7.6.0-rev10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/128257");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69794");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69793");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/533443/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_open-xchange_ox_app_suite_http_detect.nasl");
  script_mandatory_keys("open-xchange/app_suite/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!revision = get_kb_item("open-xchange/app_suite/" + port + "/revision"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
version += "." + revision;

if (version_is_less(version: version, test_version: "7.4.2.10"))
  fix = "7.4.2.10";

else if(version =~ "^7\.6" && version_is_less(version: version, test_version: "7.6.0.10"))
  fix = "7.6.0.10";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
