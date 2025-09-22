# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148344");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2022-06-29 04:30:47 +0000 (Wed, 29 Jun 2022)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-07 16:30:00 +0000 (Thu, 07 Jul 2022)");

  script_cve_id("CVE-2022-33879");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tika < 1.28.4, 2.4.x < 2.4.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_tika_http_detect.nasl");
  script_mandatory_keys("apache/tika/detected");

  script_tag(name:"summary", value:"Apache Tika is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The initial fixes in CVE-2022-30126 and CVE-2022-30973 for
  regexes in the StandardsExtractingContentHandler were insufficient, and a separate, new regex DoS
  was found in a different regex in the StandardsExtractingContentHandler.");

  script_tag(name:"affected", value:"Apache Tika version 1.28.3 and prior and version 2.4.0.");

  script_tag(name:"solution", value:"Update to version 1.28.4, 2.4.1 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/wfno8mf5nlcvbs78z93q9thgrm30wwfh");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.28.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.28.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "2.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
