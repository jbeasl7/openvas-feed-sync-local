# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wso2:identity_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106343");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2016-4311", "CVE-2016-4312");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-10-10 12:16:07 +0700 (Mon, 10 Oct 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 20:00:00 +0000 (Tue, 09 Oct 2018)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WSO2 Identity Server CSRF And XXE Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wso2_carbon_detect.nasl");
  script_mandatory_keys("wso2_carbon_identity_server/detected");

  script_tag(name:"summary", value:"WSO2 Identity Server is prone to a XML external entity (XXE)
  vulnerability.");

  script_tag(name:"insight", value:"WSO2 Identity Server is vulnerable to XXE attack which is a type of attack
  against an application that parses XML input. When Identity Server used with its XACML feature, it parses
  XACML requests and XACML policies which contain XML entries according to the XACML specification. This attack
  occurs when a XACML request or a policy containing a reference to an external entity is processed by a weakly
  configured XML parser.");

  script_tag(name:"impact", value:"An authenticated attacker may disclose local files, conduct adenial of
  service and server-side request forgery, port scanning and other system impacts on affected systems.");

  script_tag(name:"affected", value:"WSO2 Identity Server 5.1.0.");

  script_tag(name:"solution", value:"Apply the provide patch or upgrade to 5.2.0 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "5.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
