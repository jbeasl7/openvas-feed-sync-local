# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810717");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-6816");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-05 22:15:00 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-03-24 13:05:36 +0530 (Fri, 24 Mar 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat HTTP Request Line Information Disclosure Vulnerability - Windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The code that parsed the HTTP request line
  permitted invalid characters. This could be exploited, in conjunction with a
  proxy that also permitted the invalid characters but with a different
  interpretation, to inject data into the HTTP response.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to poison a web-cache, perform an XSS attack and/or obtain sensitive
  information from requests other then their own.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M1 to 9.0.0.M11,
  Apache Tomcat versions 8.5.0 to 8.5.6,
  Apache Tomcat versions 8.0.0.RC1 to 8.0.38,
  Apache Tomcat versions 7.0.0 to 7.0.72, and
  Apache Tomcat versions 6.0.0 to 6.0.47 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 9.0.0.M13,
  8.5.8, 8.0.39, 7.0.73, 6.0.48  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.48");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94461");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.73");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.39");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.8");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M13");
  script_xref(name:"URL", value:"https://qnalist.com/questions/7885204/security-cve-2016-6816-apache-tomcat-information-disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(tomPort = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:tomPort, exit_no_version:TRUE))
  exit(0);

appVer = infos["version"];
path = infos["location"];

if(appVer =~ "^[6-9]\.")
{
  if(version_in_range(version:appVer, test_version:"6.0.0", test_version2:"6.0.47"))
  {
    fix = "6.0.48";
    VULN = TRUE;
  }

  else if(version_in_range(version:appVer, test_version:"7.0.0", test_version2:"7.0.72"))
  {
    fix = "7.0.73";
    VULN = TRUE;
  }

  else if(version_in_range(version:appVer, test_version:"8.5.0", test_version2:"8.5.6"))
  {
    fix = "8.5.8";
    VULN = TRUE;
  }

  else if(version_in_range(version:appVer, test_version:"8.0.0.RC1", test_version2:"8.0.38"))
  {
    fix = "8.0.39";
    VULN = TRUE;
  }

  else if(version_in_range(version:appVer, test_version:"9.0.0.M1", test_version2:"9.0.0.M11"))
  {
    fix = "9.0.0.M13";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
    security_message(data:report, port:tomPort);
    exit(0);
  }
}
