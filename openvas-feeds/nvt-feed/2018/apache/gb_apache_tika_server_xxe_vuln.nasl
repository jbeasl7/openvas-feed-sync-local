# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813535");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2018-06-20 15:31:31 +0530 (Wed, 20 Jun 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 20:00:00 +0000 (Tue, 09 Oct 2018)");

  script_cve_id("CVE-2016-4434");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tika 0.10 - 0.12 XXE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_http_detect.nasl");
  script_mandatory_keys("apache/tika/detected");

  script_tag(name:"summary", value:"Apache Tika is prone to an XML external entity (XXE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Apache Tika failing to initialize the
  XML parser or choose handlers properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  XML External Entity (XXE) attacks via vectors involving spreadsheets in OOXML files and XMP
  metadata in PDF and other file formats.");

  script_tag(name:"affected", value:"Apache Tika version 0.10 through 1.12.");

  script_tag(name:"solution", value:"Update to version 1.13 or later.");

  script_xref(name:"URL", value:"https://mail-archives.apache.org/mod_mbox/tika-dev/201605.mbox/%3C1705136517.1175366.1464278135251.JavaMail.yahoo%40mail.yahoo.com%3E");


  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "0.10", test_version2: "1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.13");
  security_message(port: port, data:report);
  exit(0);
}

exit(99);
