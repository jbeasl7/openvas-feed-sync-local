# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809471");
  script_version("2023-09-15T16:10:33+0000");
  script_tag(name:"last_modification", value:"2023-09-15 16:10:33 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2016-11-15 13:01:25 +0530 (Tue, 15 Nov 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)");

  script_cve_id("CVE-2016-7851");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe Connect < 9.5.7 XSS Vulnerability (APSB16-35)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_http_detect.nasl");
  script_mandatory_keys("adobe/connect/detected");

  script_tag(name:"summary", value:"Adobe Connect is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as adobe connect does not adequately validate
  user inputs in the events registration module.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
  cross-site scripting attack.");

  script_tag(name:"affected", value:"Adobe Connect prior to version 9.5.7.");

  script_tag(name:"solution", value:"Update to version 9.5.7 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb16-35.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94152");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "9.5.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
