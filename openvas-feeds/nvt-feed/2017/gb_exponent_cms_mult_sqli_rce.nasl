# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exponentcms:exponent_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108093");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2016-7400", "CVE-2016-7565", "CVE-2016-7780", "CVE-2016-7781",
                "CVE-2016-7782", "CVE-2016-7783", "CVE-2016-7784", "CVE-2016-7788",
                "CVE-2016-7789", "CVE-2016-7790", "CVE-2016-7791", "CVE-2016-9019",
                "CVE-2016-9020", "CVE-2016-9087");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-27 02:29:00 +0000 (Tue, 27 Feb 2018)");
  script_tag(name:"creation_date", value:"2017-03-09 12:45:17 +0100 (Thu, 09 Mar 2017)");
  script_name("Exponent CMS < 2.4.0 Multiple SQLi and RCE Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_exponet_cms_detect.nasl");
  script_mandatory_keys("ExponentCMS/installed");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Nov/12");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/139484/Exponent-CMS-2.3.9-SQL-Injection.html");
  script_xref(name:"URL", value:"http://www.exponentcms.org/news/version-2-4-0-released");

  script_tag(name:"summary", value:"Exponent CMS is prone to multiple SQL injection (SQLi) and
  remote code execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to e.g dump database data out to a malicious server or execute code
  via the /install/index.php setup tool.");

  script_tag(name:"affected", value:"Exponent CMS 2.3.9 and earlier.");

  script_tag(name:"solution", value:"Upgrade to version 2.4.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2.4.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.4.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
