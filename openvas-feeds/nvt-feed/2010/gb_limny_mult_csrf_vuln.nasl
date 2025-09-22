# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:limny:limny";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800296");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0709");
  script_name("Limny < 2.01 Multiple CSRF Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_limny_detect.nasl");
  script_mandatory_keys("limny/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38616");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56318");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11478");

  script_tag(name:"insight", value:"Multiple flaws are caused by improper validation of user-supplied input,
  which allows users to perform certain actions via HTTP requests without
  performing any validity checks to verify the requests.");

  script_tag(name:"solution", value:"Update to version 2.01 or later.");

  script_tag(name:"summary", value:"Limny is prone to multiple cross-site request forgery (CSRF) vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to change the administrative
  password or email address and add a new user by tricking an administrative user
  into visiting a malicious web site.");

  script_tag(name:"affected", value:"Limny version 2.0.");

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

if( version_is_less_equal( version:vers, test_version:"2.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.01" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
