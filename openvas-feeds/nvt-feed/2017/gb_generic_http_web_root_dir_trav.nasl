# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106756");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-04-18 14:50:27 +0200 (Tue, 18 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  # nb:
  # - Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #   avoid too large diffs when adding a new CVE
  # - A CVSSv2 score above is used which is not necessarily the scoring attached to the CVEs below.
  #   This was done on purpose as some have some too high or wrong scoring (e.g. some have a A:H
  #   attached) currently
  script_cve_id("CVE-2010-10012", # nb: See https://www.exploit-db.com/exploits/15861
                "CVE-2010-2307",
                "CVE-2010-4231",
                "CVE-2014-2323",
                "CVE-2015-2166",
                "CVE-2015-5688",
                "CVE-2017-11456",
                "CVE-2017-16806",
                "CVE-2018-10201",
                "CVE-2018-10956",
                "CVE-2018-14064",
                "CVE-2018-18778",
                "CVE-2018-19326",
                "CVE-2018-7490",
                "CVE-2018-7719",
                "CVE-2018-8727",
                "CVE-2019-18922",
                "CVE-2019-20085",
                "CVE-2019-7315",
                "CVE-2019-9726",
                "CVE-2020-12447",
                "CVE-2020-15050",
                "CVE-2020-24571",
                "CVE-2020-5410",
                "CVE-2021-3019",
                "CVE-2021-40978",
                "CVE-2021-41773",
                "CVE-2021-42013",
                "CVE-2022-26233",
                "CVE-2022-38794",
                "CVE-2022-45269", # nb: See https://gist.github.com/robotshell/7b97af98c5dc0cacd57e6bfac90019cd
                "CVE-2023-22855", # nb: See https://hesec.de/posts/cve-2023-22855/
                "CVE-2023-46307", # nb: See https://seclists.org/fulldisclosure/2023/Nov/9
                "CVE-2024-11303", # nb: See https://cyberdanube.com/en/en-st-polten-uas-path-traversal-in-korenix-jetport/
                "CVE-2024-41628", # nb: See https://github.com/Redshift-CyberSecurity/CVE-2024-41628/blob/main/CVE-2024-41628.py
                "CVE-2024-46327", # nb: See https://hawktesters.com/5519644d-246e-4924-b7c8-8fdf742117be/ab3b22c9-1fbf-4dbb-a1cd-8c69f6723a4a.pdf
                "CVE-2024-4956", # nb: See https://github.com/vulhub/vulhub/tree/master/nexus/CVE-2024-4956
                "CVE-2024-6049", # nb: See https://sec-consult.com/vulnerability-lab/advisory/unauthenticated-path-traversal-vulnerability-in-lawo-ag-vsm-ltc-time-sync-vtimesync/
                "CVE-2024-6394", # nb: See https://huntr.com/bounties/6df4f990-b632-4791-b3ea-f40c9ea905bf
                "CVE-2024-6746", # nb: See https://github.com/NaiboWang/EasySpider/issues/466
                "CVE-2025-46096", # nb: See the PoC on https://github.com/opensolon/solon/issues/357 (Note: It *might* only load .js files but was still added here as it might still be detected)
                "CVE-2025-5598" # nb: See https://github.com/migros/migros-security-advisories/blob/main/advisories/msec-2025-004_wf-seuerungstechnik-gmbh_airleader-master_path-traversal.md
               );
  script_name("Generic HTTP Directory Traversal / File Inclusion (Web Root) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://owasp.org/www-community/attacks/Path_Traversal");
  script_xref(name:"URL", value:"https://wiki.owasp.org/index.php/Path_Traversal");
  script_xref(name:"URL", value:"http://projects.webappsec.org/w/page/13246952/Path%20Traversal");
  script_xref(name:"URL", value:"https://owasp.org/www-community/vulnerabilities/PHP_File_Inclusion");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"Generic check for HTTP directory traversal / file inclusion
  vulnerabilities on the web root level of the remote web server.");

  script_tag(name:"vuldetect", value:"Sends various crafted HTTP requests to the web root of the
  remote web server and checks the responses.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  access paths, files or directories that should normally not be accessible by a user. This can
  result in effects ranging from disclosure of confidential information to arbitrary code
  execution.");

  script_tag(name:"affected", value:"The following products are known to be affected by the pattern
  checked in this VT:

  - No CVEs: Project Jug, Webp Server Go, GeoVision GV-SNVR0811

  - CVE-2010-10012: httpdasm version 0.92 and possibly earlier

  - CVE-2010-2307: Motorola SURFBoard cable modem SBV6120E

  - CVE-2010-4231: Camtron CMNC-200 Full HD IP Camera and TecVoz CMNC-200 Megapixel IP Camera

  - CVE-2014-2323: Lighttpd

  - CVE-2015-2166: Ericsson Drutt MSDP (Instance Monitor)

  - CVE-2015-5688: Geddy

  - CVE-2017-11456: Geneko GWR router

  - CVE-2017-16806: Ulterius Server

  - CVE-2018-10201: Ncomputing vSPace Pro 10 and 11

  - CVE-2018-10956: IPConfigure Orchid Core VMS 2.0.5

  - CVE-2018-14064: uc-http service 1.0.0 on VelotiSmart WiFi B-380 camera devices

  - CVE-2018-18778: mini_httpd

  - CVE-2018-19326: Zyxel VMG1312-B10D

  - CVE-2018-7490: uWSGI

  - CVE-2018-7719: Acrolinx Server

  - CVE-2018-8727: Mirasys DVMS Workstation 5.12.6

  - CVE-2019-18922: Allied Telesis AT-GS950/8

  - CVE-2019-20085: TVT NVMS-1000

  - CVE-2019-7315: Genie Access IP Camera

  - CVE-2019-9726: Homematic CCU3

  - CVE-2020-12447: Onkyo TX-NR585 Web Interface

  - CVE-2020-15050: Suprema BioStar2

  - CVE-2020-24571: NexusQA NexusDB

  - CVE-2020-5410: Spring Cloud Config

  - CVE-2021-3019: ffay lanproxy

  - CVE-2021-40978: mkdocs 1.2.2 built-in dev-server. Note: This CVE has been disputed by the vendor
  because the dev-server is generally seen as being insecure and shouldn't be used in production.
  Nevertheless this doesn't make this CVE void so it is included here.

  - CVE-2021-41773, CVE-2021-42013: Apache HTTP Server

  - CVE-2022-26233: Barco Control Room Management Suite

  - CVE-2022-38794: Zaver

  - CVE-2022-45269: Linx Sphere LINX 7.35.ST15

  - CVE-2023-22855: Kardex Mlog. Note: The CVE is about a remote code execution (RCE) vulnerability
  but the product is also affected by a directory traversal vulnerability and thus the CVE was added
  here.

  - CVE-2023-46307: etc-browser

  - CVE-2024-11303: Korenix JetPort

  - CVE-2024-41628: ClusterControl

  - CVE-2024-46327: VONETS VAP11G-300 v3.3.23.6.9

  - CVE-2024-4956: Nexus Repository Manager 3

  - CVE-2024-6049: Lawo AG vsm LTC Time Sync (vTimeSync)

  - CVE-2024-6394: parisneo/lollms-webui versions below v9

  - CVE-2024-6746: EasySpider 0.6.2

  - CVE-2025-46096: solon 3.1.2

  - CVE-2025-5598: WF Steuerungstechnik GmbH airleader MASTER 3.0046

  Other products might be affected as well.");

  script_tag(name:"solution", value:"Contact the vendor for a solution.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  # nb: Keep in sync with the other gb_generic_http_web_* VTs
  script_timeout(1200);

  exit(0);
}

include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

# nb:
# - First one prints out the "final" URLs below
# - Second one only prints out "skipped" URLs like e.g. "c:C:" and the like
# - In both print out a `log_message()` is used as `display()` is having problem because it would interpret e.g. `\e` wrongly.
DEBUG = FALSE;
DEBUG_SKIPPED = FALSE;

depth = get_kb_item("global_settings/dir_traversal_depth");
traversals = traversal_pattern(extra_pattern_list: make_list(""), depth: depth);
files = traversal_files();
count = 0;
max_count = 3;

# nb: Keep the "suffixes", "prefixes" and "file_path_variants" lists in sync with the ones in the
# following:
#
# - 2017/gb_generic_http_web_app_params_dir_trav.nasl
# - 2021/gb_generic_http_web_dirs_dir_trav.nasl
#
# Exception: The "static" one (and similar in the future) doesn't need to be included here as it is
# already covered in / via gb_generic_http_web_dirs_dir_trav.nasl.
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

  # Oracle GlassFish Server flaw (CVE-2017-1000029) but other environments / technologies might be
  # affected as well
  "file%3a//",

  # puppeteer-renderer (CVE-2024-36527) and Moodle LMS Jmol plugin (CVE-2025-34031) which are both
  # already checked in:
  # 2017/gb_generic_http_web_app_params_dir_trav.nasl
  # but other environments / technologies might be affected as well so it was added here in addition
  "file://"
);

# nb:
# - These two only makes sense:
#   - if we know that the target host is a Windows system OR
#   - it is unknown (will be handled later then with a "continue" in the code below)
# - If similar pattern which are Windows only are getting added here please make sure to also check
#   the "skipping" code below
if ((os_host_runs("Windows") == "yes") ||
    (os_host_runs("Windows") == "unknown")) {

  prefixes = make_list(prefixes,

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

port = http_get_port(default: 80);

foreach traversal (traversals) {

  foreach pattern (keys(files)) {

    file = files[pattern];

    foreach prefix (prefixes) {

      foreach suffix (suffixes) {

        foreach file_path_variant (file_path_variants) {

          # nb: Only do modification to the file if any encoding variant has been requested
          if (file_path_variant != "plain") {

            # nb: No slash so just continue as this is already covered in the "plain" variant
            if ("/" >!< file)
              continue;

            check_file = str_replace(string: file, find: "/", replace: file_path_variant);

          } else {
            check_file = file;
          }

          url = "/" + prefix + traversal + check_file + suffix;

          # nb:
          # - For the file we need a regex as there might be e.g. etc%5cpasswd included
          # - Kept before the next traversal pattern check on purpose
          if (file =~ "etc.+passwd" && (prefix == "c:" || prefix == "file://c:")) {
            if (DEBUG_SKIPPED) display("Skipping URL (Windows only prefix and Linux file): " + url);
            continue;
          }

          if ("C:../" >< traversal && (prefix == "c:" || prefix == "file://c:")) {
            if (DEBUG_SKIPPED) display("Skipping URL (As it e.g. would cause a duplicated 'c:C:.../'): " + url);
            continue;
          }

          if (DEBUG) log_message(data: url);

          req = http_get(port: port, item: url);

          # nb: Don't use http_keepalive_send_recv() here as embedded devices which are often vulnerable
          # shows issues when requesting a keepalive connection.
          res = http_send_recv(port: port, data: req);

          if (egrep(pattern: pattern, string: res, icase: TRUE)) {
            count++;
            vuln += http_report_vuln_url(port: port, url: url) + '\n\n';
            vuln += 'Request:\n' + chomp(req) + '\n\nResponse:\n' + chomp(res) + '\n\n\n';
            break; # nb: Reporting one suffix is enough
          }
        }
        if (count >= max_count)
          break; # nb: No need to continue with that much findings
      }
      if (count >= max_count)
        break;
    }
    if (count >= max_count)
      break;
  }
  if (count >= max_count)
    break;
}

if (vuln) {
  report = 'The following affected URL(s) were found (limited to ' + max_count + ' results):\n\n' + chomp(vuln);
  security_message(port: port, data: report);
  exit(0);
}

# nb: No "exit(99)" as the system might be still affected by one or more attached CVE(s) but just no
# HTTP service is exposed
exit(0);
