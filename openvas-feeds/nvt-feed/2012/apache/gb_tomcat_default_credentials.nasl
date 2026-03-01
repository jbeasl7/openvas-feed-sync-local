# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103550");
  script_version("2026-02-27T05:55:46+0000");
  # nb: Unlike in other VTs we're using the CVEs line by line here for easier addition of new CVEs /
  #     to avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2009-3099",
                "CVE-2009-3548",
                "CVE-2009-3843",
                "CVE-2009-4188",
                "CVE-2009-4189",
                "CVE-2010-0557",
                "CVE-2010-4094"
               );
  script_name("Apache Tomcat Manager/Host Manager/Server Status Default/Hardcoded Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2026-02-27 05:55:46 +0000 (Fri, 27 Feb 2026)");
  script_tag(name:"creation_date", value:"2012-08-22 17:19:15 +0200 (Wed, 22 Aug 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected", "ApacheTomcat/auth_required");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://tomcat.apache.org/tomcat-11.0-doc/realm-howto.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/tomcat-11.0-doc/realm-howto.html#LockOutRealm");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-10-214/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121192211/http://www.securityfocus.com/bid/36258");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121192951/http://www.securityfocus.com/bid/36954");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121193118/http://www.securityfocus.com/bid/37086");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121194133/http://www.securityfocus.com/bid/38084");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121205210/http://www.securityfocus.com/bid/44172");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210120183039/http://www.securityfocus.com/bid/79264");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210120183258/http://www.securityfocus.com/bid/79351");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-09-085/");

  script_tag(name:"summary", value:"The Apache Tomcat Manager/Host Manager/Server Status is using
  default or known hardcoded credentials.");

  script_tag(name:"vuldetect", value:"Tries to login via HTTP using known default credentials.

  Note: Newer Tomcat versions having a default 'LockOutRealm' configuration which prevents brute
  force attacks and locks the accounts for a certain amount of time. For such configurations
  existing default credentials can't be identified in a reliable way.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to upload and execute
  arbitrary code, which will facilitate a complete compromise of the affected computer.");

  script_tag(name:"solution", value:"Change the password to a strong one or remove the user from
  tomcat-users.xml.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  script_timeout(600);

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

# nb: Keep in sync with 2015/apache/sw_tomcat_admin_default_credentials.nasl
credentials = make_list(
  # Taken from:
  # - various example files / documentations
  # - https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown
  # - https://www.ikkisoft.com/stuff/TomcatSec_LucaCarettoni.pdf
  # - CVEs / descriptions within them
  # - own research
  "admin:admin",
  "admin:changethis",
  "admin:password",
  "admin:Password1",
  "admin:password1",
  "admin:vagrant",
  "both:tomcat",
  "manager:manager",
  "password:password",
  "role:changethis",
  "role1:role1",
  "role1:tomcat",
  "role1:tomcat7",
  "root:changethis",
  "root:password",
  "root:Password1",
  "root:password1",
  "root:r00t",
  "root:root",
  "root:toor",

  # Oracle freaks
  "scott:tiger",

  "tomcat:admin",
  "tomcat:changethis",

  # Sun Solaris installation
  "tomcat:j5Brn9",

  "tomcat:none",
  "tomcat:password",
  "tomcat:Password1",
  "tomcat:password1",
  "tomcat:tomcat",
  "tomcatadmin:pwd",

  # https://nvd.nist.gov/vuln/detail/CVE-2010-4094
  "ADMIN:ADMIN",

  # https://nvd.nist.gov/vuln/detail/CVE-2009-3548
  "admin:none",

  # https://github.com/seshendra/vagrant-ubuntu-tomcat7/blob/abd0a6c9cf08f8db642bde33ce7491259247ce18/manifests/default.pp#L49-L50
  "admin:tomcat",

  # https://nvd.nist.gov/vuln/detail/CVE-2009-4189, https://nvd.nist.gov/vuln/detail/CVE-2009-3099 and https://nvd.nist.gov/vuln/detail/CVE-2009-3843
  "ovwebusr:OvW*busr1",

  # https://nvd.nist.gov/vuln/detail/CVE-2009-4188
  "j2deployer:j2deployer",

  # https://github.com/apache/tomcat/blob/2b8f9665dbfb89c78878784cd9b63d2b976ba623/webapps/manager/WEB-INF/jsp/403.jsp#L66
  "tomcat:s3cret",

  # https://nvd.nist.gov/vuln/detail/CVE-2010-0557
  "cxsdk:kdsxc",

  # XAMPP from https://www.apachefriends.org/index.html
  "xampp:xampp",

  # QLogic QConvergeConsole from http://www.qlogic.com/
  "QCC:QLogic66",

  # OWASP Broken Web Applications Project
  "root:owaspbwa",

  # HAPI FHIR from http://hapifhir.io/
  "fhir:FHIRDefaultPassword",

  # Few shown at https://www.deepreflect.net/2009/07/18/miaoo-tomcat-su-debian/
  # nb: The "leo" one has been excluded, this seems to be too specific and just a not used example
  "tomcat:pwd",
  "both:pwd",
  "role1:pwd",
  "manager:pwd",

  # From page 27 of this:
  # https://cockpitci.itrust.lu/wp-content/uploads/2015/04/CockpitCI-D5.4-CockpitCI-System-Factory-Trials-Report.pdf
  "admin:cockpitcomm"
);

host = http_host_name( dont_add_port:TRUE );

vuln = FALSE;
report = ""; # nb: To make openvas-nasl-lint happy...

# nb: Set by gb_apache_tomcat_consolidation.nasl
authRequireUrls = get_kb_list( "www/" + host + "/" + port + "/ApacheTomcat/auth_required" );
if( isnull( authRequireUrls ) )
  exit( 0 );

# Sort to not report changes on delta reports if just the order is different
authRequireUrls = sort( authRequireUrls );

foreach url( authRequireUrls ) {

  foreach credential( credentials ) {

    user_pass = split( credential, sep:":", keep:FALSE );

    user = chomp( user_pass[0] );
    pass = chomp( user_pass[1] );

    if( tolower( pass ) == "none" ) pass = "";

    userpass = string( user, ":", pass );
    userpass64 = base64( str:userpass );

    headers = make_array( "Authorization", "Basic " + userpass64 );

    req = http_get_req( port:port, url:url, add_headers:headers );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
    if( ! res || res !~ "^HTTP/1\.[01]" )
      continue;

    if( pass == "" )
      pass_report = "an empty password";
    else
      pass_report = 'password "' + pass + '"';

    if( res =~ "^HTTP/1\.[01] 200" && "Tomcat Web Application Manager" >< res ) {
      report += "It was possible to login into the Tomcat Manager at " + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + ' using user "' + user + '" with ' + pass_report + '\n\n';
      vuln = TRUE;
    } else if( res =~ "^HTTP/1\.[01]" && "Tomcat Virtual Host Manager" >< res ) {
      report += "It was possible to login into the Tomcat Host Manager at " + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + ' using user "' + user + '" with ' + pass_report + '\n\n';
      vuln = TRUE;
    } else if( res =~ "^HTTP/1\.[01]" && "Server Status" >< res && "Complete Server Status" >< res ) {
      report += "It was possible to login into the Tomcat Server Status at " + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + ' using user "' + user + '" with ' + pass_report + '\n\n';
      vuln = TRUE;
    }
  }
}

if( vuln ) {
  security_message( port:port, data:chomp( report ) );
  exit( 0 );
}

exit( 99 );
