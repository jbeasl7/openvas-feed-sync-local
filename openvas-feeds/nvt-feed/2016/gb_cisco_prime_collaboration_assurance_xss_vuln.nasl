# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_collaboration_assurance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809770");
  script_version("2024-12-04T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-12-04 05:05:48 +0000 (Wed, 04 Dec 2024)");
  script_tag(name:"creation_date", value:"2016-12-22 19:49:38 +0530 (Thu, 22 Dec 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-22 18:30:00 +0000 (Thu, 22 Dec 2016)");

  script_cve_id("CVE-2016-9200");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Prime Collaboration Assurance Cross-Site Scripting Vulnerability (cisco-sa-20161207-pca)");

  script_category(ACT_GATHER_INFO);

  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_pca_version.nasl");
  script_mandatory_keys("cisco_pca/detected");

  script_tag(name:"summary", value:"Cisco Prime Collaboration Assurance is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient input validation
  of some parameters that are passed to the web server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary script code in the context of the affected site
  or allow the attacker to access sensitive browser-based information.");

  script_tag(name:"affected", value:"Cisco Prime Collaboration Assurance versions 10.5.1 and
  10.6.0.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-pca");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut43268");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94806");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE))
  exit(0);

if(version =~ "^10\.[56]") {
  if(version_is_equal(version:version, test_version:"10.5.1") ||
     version_is_equal(version:version, test_version:"10.6.0")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"See references");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
