# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:liferay:liferay_portal";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143624");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-03-23 04:50:18 +0000 (Mon, 23 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-30 02:31:00 +0000 (Sat, 30 Jan 2021)");

  script_cve_id("CVE-2020-7961");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Liferay Portal JSON Web Service RCE Vulnerabilities (CST-7111, CST-7205)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_liferay_consolidation.nasl");
  script_mandatory_keys("liferay/portal/detected");

  script_tag(name:"summary", value:"Liferay Portal is prone to multiple remote code execution
  (RCE) vulnerabilities in the JSON web service.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CST-7111: RCE via JSON deserialization (LPS-88051/LPE-165981)

  The JSONDeserializer of Flexjson allows the instantiation of arbitrary classes and the invocation
  of arbitrary setter methods.

  - CST-7205: Unauthenticated Remote code execution via JSONWS (LPS-97029/CVE-2020-7961)

  The JSONWebServiceActionParametersMap of Liferay Portal allows the instantiation of arbitrary
  classes and invocation of arbitrary setter methods.");

  script_tag(name:"affected", value:"Liferay Portal version 7.2.0 and prior.");

  script_tag(name:"solution", value:"Update to version 7.2.1 or later.");

  script_xref(name:"URL", value:"https://portal.liferay.dev/learn/security/known-vulnerabilities/-/asset_publisher/HbL5mxmVrnXW/content/id/113765197");
  script_xref(name:"URL", value:"https://portal.liferay.dev/learn/security/known-vulnerabilities/-/asset_publisher/HbL5mxmVrnXW/content/id/117954271");
  script_xref(name:"URL", value:"https://issues.liferay.com/browse/LPS-88051");
  script_xref(name:"URL", value:"https://issues.liferay.com/browse/LPE-16598");
  script_xref(name:"URL", value:"https://issues.liferay.com/browse/LPS-97029");
  script_xref(name:"URL", value:"https://liferay.dev/blogs/-/blogs/security-patches-for-liferay-portal-6-2-7-0-and-7-1");
  script_xref(name:"URL", value:"https://liferay.dev/blogs/-/blogs/liferay-portal-7-2-ce-ga2-release");
  script_xref(name:"URL", value:"https://codewhitesec.blogspot.com/2020/03/liferay-portal-json-vulns.html");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

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

if (version_is_less(version: version, test_version: "7.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
