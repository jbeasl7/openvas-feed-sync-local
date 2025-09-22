# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piwigo:piwigo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107116");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-12-30 13:26:09 +0700 (Fri, 30 Dec 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-03 19:00:00 +0000 (Tue, 03 Jan 2017)");

  script_cve_id("CVE-2016-10084", "CVE-2016-10085");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo < 2.8.5 RFI Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to a remote file inclusion (RFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote file inclusion vulnerability allows remote attackers to
  include arbitrary remote files and execute PHP code on the affected computer in the context of the webserver process.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to obtain sensitive information,
  which can lead to launching further attacks.");

  script_tag(name:"affected", value:"Piwigo prior to 2.8.5.");

  script_tag(name:"solution", value:"Update to version 2.8.5 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95164");
  script_xref(name:"URL", value:"http://piwigo.org/releases/2.8.5");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
