# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814054");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2018-09-27 15:38:59 +0530 (Thu, 27 Sep 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-12 20:15:00 +0000 (Tue, 12 Nov 2019)");

  script_cve_id("CVE-2018-11761", "CVE-2018-11796");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tika < 1.19.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_http_detect.nasl");
  script_mandatory_keys("apache/tika/detected");

  script_tag(name:"summary", value:"Apache Tika is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because apache tika's XML parsers were not
  configured to limit entity expansion.

  NOTE: In Apache Tika 1.19 (CVE-2018-11761), added an entity expansion limit for XML parsing.
  However, Tika reuses SAXParsers and calls reset() after each parse, which, for Xerces2 parsers,
  as per the documentation, removes the user-specified SecurityManager and thus removes entity
  expansion limits after the first parse. Apache Tika 1.19 is therefore still vulnerable to entity
  expansions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service condition.");

  script_tag(name:"affected", value:"Apache Tika version 1.19 and prior.");

  script_tag(name:"solution", value:"Update to version 1.19.1 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/5553e10bba5604117967466618f219c0cae710075819c70cfb3fb421@%3Cdev.tika.apache.org%3E");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/5553e10bba5604117967466618f219c0cae710075819c70cfb3fb421@%3Cdev.tika.apache.org%3E");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.19.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.19.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
