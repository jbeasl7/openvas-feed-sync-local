# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802453");
  script_version("2023-12-20T05:05:58+0000");
  script_cve_id("CVE-2012-0307", "CVE-2012-0308", "CVE-2012-3579", "CVE-2012-3580",
                "CVE-2012-3581");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-09-04 17:27:04 +0530 (Tue, 04 Sep 2012)");
  script_name("Symantec Messaging Gateway < 10.0 Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027449");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55138");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55141");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55142");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55143");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/524060");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50435");
  script_xref(name:"URL", value:"https://www.hkcert.org/my_url/en/alert/12082901");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&suid=20120827_00");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
  restrictions, disclose certain sensitive information and conduct cross-site scripting and request forgery attacks.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway version 9.5.x.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Certain input passed via web or email content is not properly sanitised
  before being returned to the user.

  - The application allows users to perform certain actions via HTTP requests
  without performing proper validity checks to verify the requests.

  - An error within the management interface can be exploited to perform
  otherwise restricted actions(modify the underlying web application).

  - An SSH default passworded account that could potentially be leveraged by
  an unprivileged user to attempt to gain additional privilege access.

  - Disclose of excessive component version information during successful
  reconnaissance.");

  script_tag(name:"solution", value:"Upgrade to Symantec Messaging Gateway version 10.0 or later.");

  script_tag(name:"summary", value:"Symantec Messaging Gateway is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

# If optimize_test = no
if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port(default:22);

if(ssh_dont_try_login(port:port))
  exit(0);

# nb: No need to continue/start if we haven't received any banner...
if(!ssh_get_serverbanner(port:port))
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

user = "support";
pass = "symantec";

login = ssh_login(socket:soc, login:user, password:pass);
if(login == 0) {

  cmd = "cat /etc/Symantec/SMSSMTP/resources";
  res = ssh_cmd(socket:soc, cmd:cmd);

  if(res && "/Symantec/Brightmail" >< res && "SYMANTEC_BASEDIR" >< res) {
    report = 'It was possible to login as user "' + user + '" with password "' + pass + '" and to execute the "' + cmd + '" command. Result:\n\n' + res;
    security_message(port:port, data:report);
    close(soc);
    exit(0);
  }
}

close(soc);
exit(0);
