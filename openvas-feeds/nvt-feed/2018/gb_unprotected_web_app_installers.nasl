# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107307");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-05-07 12:00:20 +0200 (Mon, 07 May 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"5.0");
  script_name("Unprotected Web App / Device Installers (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "sw_magento_detect.nasl",
                      "gb_wordpress_http_detect.nasl", "osticket_http_detect.nasl",
                      "gb_dotnetnuke_consolidation.nasl", "gb_tikiwiki_http_detect.nasl",
                      "gb_nuxeo_platform_detect.nasl", "gb_owncloud_http_detect.nasl",
                      "gb_dolibarr_http_detect.nasl", "gb_atlassian_jira_http_detect.nasl",
                      "gb_lucee_consolidation.nasl", "gb_froxlor_http_detect.nasl",
                      "gb_projectsend_http_detect.nasl", "gb_chamilo_http_detect.nasl",
                      "gb_mautic_http_detect.nasl", "global_settings.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_openmage_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify installation/setup pages of
  various web apps/devices that are publicly accessible and not protected by e.g. account
  restrictions or having their setup finished.");

  script_tag(name:"vuldetect", value:"Enumerate the remote web server and check if unprotected
  web apps/devices are accessible for installation.");

  script_tag(name:"impact", value:"It is possible to install or reconfigure the software. In doing
  so, the attacker could overwrite existing configurations. It could be possible for the attacker to
  gain access to the base system");

  script_tag(name:"solution", value:"Setup and/or installation pages for Web Apps should not be
  publicly accessible via a web server. Restrict access to it, remove it completely or finish the
  setup of the application / device.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  script_timeout(900);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

# nb:
# - We can't save an array within an array so we're using:
#   - array index = the file to check
#   - array value = the description and the regex of the checked file separated with #-#. Optional a
#                   third entry separated by #-# containing an "extra_check" for http_vuln_check()
# - http_vuln_check() is used for the HTTP request gathering. This function is doing a case
#   insensitive regex pattern match internally so we don't need to have special handling like e.g.
#   "(Jira|JIRA)" below

genericfiles = make_array(

  # nb: phpipam has a separate entry below but this one here has been kept as the product might have
  # behaved differently back then in 2018.
  "/index.php", 'Installer / Setup-Tool of multiple vendors#-#<title>((Microweber|phpipam|VoIPmonitor) installation|Installation|WackoWiki Installation|(Piwik|Matomo) .* &rsaquo; Installation|LimeSurvey installer)</title>',

  "/index.php?module=Users&parent=Settings&view=SystemSetup", 'VTiger CMS Installation tool.#-#<title>Install</title>',

  "/index.php/index/install", 'Open Journal Systems installer#-#<title>O(JS|MP) Installation</title>',

  "/install.php", 'Installer / Setup-Tool of multiple vendors#-#<title>((Moodle|PHP-Fusion) Install|Piwigo * - Installation|Monstra :: Install|Kohana Installation|SMF Installer|vtiger CRM .* - Configuration Wizard - Welcome)</title>',

  "/setup.php", 'Installer / Setup-Tool of multiple versions of Zabbix#-#<title>Installation</title>|class="setup_wizard setup_wizard_welcome"|Check of pre-requisites',

  "/admin/install", 'Orchestra Platform installer#-#<title>Installer &mdash; Orchestra Platform</title>',

  "/admin#/mode", 'NetIQ Web installer#-#<title>Installation</title>',

  "/cb_install/", 'ClipBucket installer#-#<title>ClipBucket .* Installer</title>',

  "/centreon/install/setup.php", 'Centreon monitoring tool installer#-#<title>Centreon Installation</title>',

  "/contao/install.php", 'Contao OpenSource CMS installer#-#(GNU GENERAL PUBLIC LICENSE|enter a password to prevent)',
  "/contao/install", 'Contao OpenSource CMS installer#-#GNU GENERAL PUBLIC LICENSE',

  "/farcry/core/webtop/install/index.cfm", 'FarCry Core installer#-#<title>FarCry Core Installer</title>',

  "/Install", 'Installer / Setup-Tool of multiple vendors#-#(<h1>Install concrete5</h1>|<title>(Group-Office|EspoCRM|nopCommerce) Installation|PrestaShop (Installation Assistant|Wizard Installer)|Subrion CMS Web Installer</title>|install SmartStore.NET now?|Nextpost Installation)',

  "/install/index.php",  'AChecker or OpenCart installer#-#<title>(OpenCart - Installation|AChecker Installation|forma.lms installer)</title>',

  "/install/system-compatibility", 'Acelle Mail installer#-#<title>Requirement - Acelle Installation</title>',

  "/installation/default.asp", 'vp-asp shopping cart setup page#-#<title>Installation Wizard</title>',

  "/installation/index.php", 'Joomla Web installer#-#<title>((Joomla! Web|JoomlaPack|Akeeba Backup|Mambo - Web) Installer)</title>',

  "/home/index.php", 'XPress Engine CMS installer#-#<title>XE Installation</title>',

  "/module.php/core/frontpage_welcome.php", 'simpleSAMLphp Installer.#-#<title>simpleSAMLphp installation page</title>',

  "/recovery/install/", 'Shopware installer#-#<title>Shopware .* - Installer</title>',

  "/setup/index.php", 'CubeCart / phpMyAdmin installer#-#<title>(CubeCart .* Installer|phpMyAdmin setup)</title>',

  "/setup/setup.php", 'WaWision WaWi, ERP CRM installer#-#<title>WaWision Installer</title>',

  "/tao/install/", 'TAO installer#-#<title>TAO Installation</title>',

  "/install/", "phpBB installer#-#<title>Introduction</title>#-#<span>Install</span></a></li>",

  "/v1/settings/first-login", 'Rancher first login value is set to true#-#"value"\\s*:\\s*"true"',
  "/v3/settings/first-login", 'Rancher first login value is set to true#-#"value"\\s*:\\s*"true"',

  "/admin/install.php", "MantisBT installer#-#<title>Administration - Installation - MantisBT</title>",

  "/index.php?page=install", "phpipam installer#-#(<title>phpipam installation</title>|Welcome to phpipam installation wizard)",

  # nb: There are also separate Magento and OpenMage checks below using the same endpoint
  "/index.php/install/", 'XLRstats installer#-#<title>XLRstats Installation</title>',

  # nb: "/setup/start" is redirecting to "/setup/unlock" if already configured / installed
  "/setup/start", "GitHub Enterprise installer#-#<title>Setup GitHub Enterprise</title>",

  # If not configured yet (depends on the version)
  # [{"step":"user","done":false},{"step":"core_config","done":false},{"step":"analytics","done":false},{"step":"integration","done":false}]
  # or:
  # [{"done": false, "step": "user"}]
  # and if configured / installed:
  # [{"step":"user","done":true},{"step":"core_config","done":true},{"step":"analytics","done":true},{"step":"integration","done":true}]
  #
  "/api/onboarding", 'Home Assistant setup#-#(\\{\\s*"step"\\s*:\\s*"user"\\s*,\\s*"done"\\s*:\\s*false\\}|\\{\\s*"done"\\s*:\\s*false\\s*,\\s*"step"\\s*:\\s*"user"\\})#-#^\\[[^]+\\]'
);

# nb: Used later without the http_cgi_dirs() result
rootdirfiles = make_array(
  "/login.htm", 'D-Link Router setup page#-#<title>Welcome to D-Link Router Setup</title>',

  "/adm/wizard.asp", "Intelbras NCLOUD setup page#-#(<script>dw\(MM_easywizard\)</script>|\.\./nbox/first_page\.png)#-#<title>Roteador NCLOUD",

  "/setup/", 'Ubiquiti UniFi Network application setup page#-#<base href="/setup/"/>#-#^Set-Cookie\\s*:\\s*unifises=.+'
);

magentofiles = make_array(
  "/downloader/", 'Magento installer#-#<title>Magento Installation Wizard</title>',
  "/index.php/install/", 'Magento installer#-#<title>Magento Installation</title>'
);

wordpressfiles = make_array(
  "/wp-admin/install.php", 'WordPress installer#-#<title>WordPress &rsaquo; Installation</title>#-#="install\\.php\\?step=',
  "/wp-admin/setup-config.php", 'WordPress installer#-#<title>WordPress &rsaquo; Setup Configuration File</title>'
);

osticketfiles = make_array(
  "/setup/install.php", 'osTicket installer#-#<title>osTicket Installer</title>'
);

dotnetnukefiles = make_array(
  "/Install/InstallWizard.aspx", 'DotNetNuke CMS installation tool#-#<title>        Installation</title>'
);

tikiwikifiles = make_array(
  "/tiki-install.php", "Tiki wiki cms groupware installer#-#<title>Tiki Installer</title>"
);

nuxeo_platformfiles = make_array(
  "/nuxeo/", 'Nuxeo Platform installer#-#<title>Nuxeo Platform Installation wizard</title>'
);

ocfiles = make_array(
  "/", 'ownCloud installer#-#ownCloud.*</title>#-#(<legend>(Configure the database|Performance warning|Create an <strong>admin account</strong>)</legend>|value="Finish setup" data-finishing="Finishing|placeholder="Database user"|placeholder="Database password")',
  "/index.php", 'ownCloud installer#-#ownCloud.*</title>#-#(<legend>(Configure the database|Performance warning|Create an <strong>admin account</strong>)</legend>|value="Finish setup" data-finishing="Finishing|placeholder="Database user"|placeholder="Database password")'
);

dolibarrfiles = make_array(
  "/install/check.php", "Dolibarr ERP/CRM installer / updater#-#<title>Dolibarr install or upgrade</title>"
);

jirafiles = make_array(
  # <title>JIRA - JIRA setup</title>
  # <title>Jira - Jira setup</title>
  "/secure/SetupMode!default.jspa", "Atlassian Jira installer#-#<title>Jira - Jira setup</title>"
);

luceefiles = make_array(
  "/lucee/admin/web.cfm", 'Luceee Web Administrator allowing to set a new password#-#(<title>New Password - Lucee Web Administrator</title>|<th scope="row" class="right" nowrap="nowrap">Retype new password</th>)',
  "/lucee/admin/server.cfm", 'Luceee Server Administrator allowing to set a new password#-#(<title>New Password - Lucee Server Administrator</title>|<th scope="row" class="right" nowrap="nowrap">Retype new password</th>)'
);

froxlorfiles = make_array(
  "/", "Froxlor installer#-#(Froxlor Server Management Panel - Installation|<p>It seems that Froxlor has not been installed yet\.</p>)",
  "/index.php", "Froxlor installer#-#(Froxlor Server Management Panel - Installation|<p>It seems that Froxlor has not been installed yet\.</p>)"
);

mauticfiles = make_array(
  "/index.php/installer", "Mautic installer#-#Mautic Installation - Environment Check",
  "/installer", "Mautic installer#-#Mautic Installation - Environment Check"
);

projectsendfiles = make_array(
  "/install/make-config.php", 'ProjectSend installer#-#<title>Install &raquo; ProjectSend</title>'
);

chamilofiles = make_array(
  "/", 'Chamilo installer#-#<title>Chamilo has not been installed</title>',
  "/index.php", 'Chamilo installer#-#<title>Chamilo has not been installed</title>'
);

openmagefiles = make_array(
  "/index.php/install/", 'OpenMage installer#-#<title>OpenMage (LTS )?Installation Wizard</title>'
);

global_var report, VULN;

function check_files( filesarray, dirlist, port ) {

  local_var filesarray, dirlist, port, dir, file, infos, extra, url;

  foreach dir( dirlist ) {

    if( dir == "/" ) dir = "";

    foreach file( keys( filesarray ) ) {

      # infos[0] contains the description, infos[1]  the regex. Optionally infos[2] contains an extra_check for http_vuln_check
      infos = split( filesarray[file], sep:"#-#", keep:FALSE );
      if( max_index( infos ) < 2 ) continue; # Something is wrong with the provided info...

      if( max_index( infos ) > 2 )
        extra = make_list( infos[2] );
      else
        extra = NULL;

      url = dir + file;

      if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:infos[1], extra_check:extra, usecache:TRUE ) ) {
        report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + " - " + infos[0];
        VULN = TRUE;
      }
    }
  }
}

report = 'The following web app/device installers are unprotected/have not finished their setup and are publicly accessible (URL:Description):\n';

port = http_get_port( default:80 );

dirlist = make_list_unique( "/", http_cgi_dirs( port:port ) );
check_files( filesarray:genericfiles, dirlist:dirlist, port:port );

check_files( filesarray:rootdirfiles, dirlist:make_list( "/" ), port:port );

madirs = get_app_location( port:port, cpe:"cpe:/a:magentocommerce:magento", nofork:TRUE );
if( madirs )
  magentodirlist = make_list_unique( madirs, dirlist );
else
  magentodirlist = dirlist;
check_files( filesarray:magentofiles, dirlist:magentodirlist, port:port );

wpdirs = get_app_location( port:port, cpe:"cpe:/a:wordpress:wordpress", nofork:TRUE );
if( wpdirs )
  wordpressdirlist = make_list_unique( wpdirs, dirlist );
else
  wordpressdirlist = dirlist;
check_files( filesarray:wordpressfiles, dirlist:wordpressdirlist, port:port );

osdirs = get_app_location( port:port, cpe:"cpe:/a:osticket:osticket", nofork:TRUE );
if( osdirs )
  osticketdirlist = make_list_unique( osdirs, dirlist );
else
  osticketdirlist = dirlist;
check_files( filesarray:osticketfiles, dirlist:osticketdirlist, port:port );

dotnetdirs = get_app_location( port:port, cpe:"cpe:/a:dotnetnuke:dotnetnuke", nofork:TRUE );
if( dotnetdirs )
  dotnetnukedirlist = make_list_unique( dotnetdirs, dirlist );
else
  dotnetnukedirlist = dirlist;
check_files( filesarray:dotnetnukefiles, dirlist:dotnetnukedirlist, port:port );

tikidirs = get_app_location( port:port, cpe:"cpe:/a:tiki:tikiwiki_cms%2fgroupware", nofork:TRUE );
if( tikidirs )
  tikiwikidirlist = make_list_unique( tikidirs, dirlist );
else
  tikiwikidirlist = dirlist;
check_files( filesarray:tikiwikifiles, dirlist:tikiwikidirlist, port:port );

nuxeodirs = get_app_location( port:port, cpe:"cpe:/a:nuxeo:platform", nofork:TRUE );
if( nuxeodirs )
  nuxeo_platformdirlist = make_list_unique( nuxeodirs, dirlist );
else
  nuxeo_platformdirlist = dirlist;
check_files( filesarray:nuxeo_platformfiles, dirlist:nuxeo_platformdirlist, port:port );

ocdirs = get_app_location( port:port, cpe:"cpe:/a:owncloud:owncloud", nofork:TRUE );
if( ocdirs )
  ocdirlist = make_list_unique( ocdirs, dirlist );
else
  ocdirlist = dirlist;
check_files( filesarray:ocfiles, dirlist:ocdirlist, port:port );

dolibarrdirs = get_app_location( port:port, cpe:"cpe:/a:dolibarr:dolibarr", service:"www", nofork:TRUE );
if( dolibarrdirs )
  dolibarrdirlist = make_list_unique( dolibarrdirs, dirlist );
else
  dolibarrdirlist = dirlist;
check_files( filesarray:dolibarrfiles, dirlist:dolibarrdirlist, port:port );

jiradirs = get_app_location( port:port, cpe:"cpe:/a:atlassian:jira", service:"www", nofork:TRUE );
if( jiradirs )
  jiradirlist = make_list_unique( jiradirs, dirlist );
else
  jiradirlist = dirlist;
check_files( filesarray:jirafiles, dirlist:jiradirlist, port:port );

luceedirs = get_app_location( port:port, cpe:"cpe:/a:lucee:lucee_server", service:"www", nofork:TRUE );
if( luceedirs )
  luceedirlist = make_list_unique( luceedirs, dirlist );
else
  luceedirlist = dirlist;
check_files( filesarray:luceefiles, dirlist:luceedirlist, port:port );

froxlordirs = get_app_location( port:port, cpe:"cpe:/a:froxlor:froxlor", service:"www", nofork:TRUE );
if( froxlordirs )
  froxlordirlist = make_list_unique( froxlordirs, dirlist );
else
  froxlordirlist = dirlist;
check_files( filesarray:froxlorfiles, dirlist:froxlordirlist, port:port );

mauticdirs = get_app_location( port:port, cpe:"cpe:/a:mautic:mautic", service:"www", nofork:TRUE );
if( mauticdirs )
  mauticdirlist = make_list_unique( mauticdirs, dirlist );
else
  mauticdirlist = dirlist;
check_files( filesarray:mauticfiles, dirlist:mauticdirlist, port:port );

projectsenddirs = get_app_location( port:port, cpe:"cpe:/a:projectsend:projectsend", service:"www", nofork:TRUE );
if( projectsenddirs )
  projectsenddirlist = make_list_unique( projectsenddirs, dirlist );
else
  projectsenddirlist = dirlist;
check_files( filesarray:projectsendfiles, dirlist:projectsenddirlist, port:port );

chamilodirs = get_app_location( port:port, cpe:"cpe:/a:chamilo:chamilo_lms", service:"www", nofork:TRUE );
if( chamilodirs )
  chamilodirlist = make_list_unique( chamilodirs, dirlist );
else
  chamilodirlist = dirlist;
check_files( filesarray:chamilofiles, dirlist:chamilodirlist, port:port );

openmagedirs = get_app_location( port:port, cpe:"cpe:/a:openmage:openmage", service:"www", nofork:TRUE );
if( openmagedirs )
  openmagedirlist = make_list_unique( openmagedirs, dirlist );
else
  openmagedirlist = dirlist;
check_files( filesarray:openmagefiles, dirlist:openmagedirlist, port:port );

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
