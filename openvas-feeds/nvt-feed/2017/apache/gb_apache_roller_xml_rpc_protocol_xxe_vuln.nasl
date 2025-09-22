# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:roller";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812233");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-12-01 11:21:50 +0530 (Fri, 01 Dec 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-06 20:38:00 +0000 (Mon, 06 May 2019)");

  script_cve_id("CVE-2014-0030");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Roller < 5.0.3 XXE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_roller_http_detect.nasl");
  script_mandatory_keys("apache/roller/detected");

  script_tag(name:"summary", value:"Apache Roller is prone to an XML external entity (XXE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to XML-RPC protocol support in Apache
  Roller.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to conduct
  XML External Entity (XXE) attacks via unspecified vectors. This vulnerability exists even if
  XML-RPC is disabled via the Roller Admin Console.");

  script_tag(name:"affected", value:"Apache Roller version 4.0.0, 4.0.1, 5.0, 5.0.1 and 5.0.2. The
  unsupported Roller 3.1 release is also affected.");

  script_tag(name:"solution", value:"Update to version 5.0.3 or later.");

  script_xref(name:"URL", value:"https://liftsecurity.io/advisories/Apache_Roller_XML-RPC_susceptible_to_XXE");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101230");
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

if (version_is_less(version: version, test_version: "5.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
