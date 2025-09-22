# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153629");
  script_version("2025-07-16T05:43:53+0000");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"creation_date", value:"2024-12-12 07:24:23 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 16:30:19 +0000 (Tue, 15 Jul 2025)");

  script_cve_id("CVE-2024-53677");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts Security Update (S2-067)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_tag(name:"summary", value:"Apache Struts is prone to a file upload logic vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker can manipulate file upload params to enable paths
  traversal and under some circumstances this can lead to uploading a malicious file which can be
  used to perform remote code execution.");

  script_tag(name:"affected", value:"Apache Struts version 2.0.0 through 2.3.37, 2.5.0 through
  2.5.33 and 6.0.0 through 6.3.0.2.");

  script_tag(name:"solution", value:"Update to version 6.4.0 or later.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-067");
  script_xref(name:"URL", value:"https://github.com/TAM-K592/CVE-2024-53677-S2-067");
  script_xref(name:"URL", value:"https://isc.sans.edu/diary/31520");
  script_xref(name:"Advisory-ID", value:"S2-067");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "2.3.37") ||
    version_in_range(version: version, test_version: "2.5.0", test_version2: "2.5.33") ||
    version_in_range(version: version, test_version: "6.0.0", test_version2: "6.3.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
