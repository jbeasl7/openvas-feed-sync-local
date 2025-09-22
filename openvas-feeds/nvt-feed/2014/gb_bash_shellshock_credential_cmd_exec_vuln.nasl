# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:gnu:bash";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804490");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2014-09-26 13:50:37 +0530 (Fri, 26 Sep 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-01 21:38:00 +0000 (Mon, 01 Feb 2021)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-6271");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GNU Bash Environment Variable Handling RCE Vulnerability (Shellshock, Linux/Unix SSH Login, CVE-2014-6271) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_gnu_bash_detect_lin.nasl");
  script_mandatory_keys("bash/linux/detected");
  script_exclude_keys("ssh/force/pty");

  script_tag(name:"summary", value:"GNU Bash is prone to a remote command execution (RCE)
  vulnerability dubbed 'Shellshock'.");

  script_tag(name:"vuldetect", value:"Logs into the target machine via SSH, sends a crafted SSH
  command and checks the response.");

  script_tag(name:"insight", value:"GNU bash contains a flaw that is triggered when evaluating
  environment variables passed from another environment. After processing a function definition,
  bash continues to process trailing strings.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote or local attackers to
  inject shell commands, allowing local privilege escalation or remote command execution depending
  on the application vector.");

  script_tag(name:"affected", value:"GNU Bash through 4.3.");

  script_tag(name:"solution", value:"Apply the appropriate patch provided by the vendor.");

  script_xref(name:"URL", value:"https://access.redhat.com/security/vulnerabilities/shellshock");
  script_xref(name:"URL", value:"https://access.redhat.com/solutions/1207723");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1141597");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210420171418/https://blogs.akamai.com/2014/09/environment-bashing.html");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2014/09/24/bash-shellshock-vulnerability");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2014/09/24/bash-remote-code-execution-vulnerability-cve-2014-6271");
  script_xref(name:"URL", value:"https://shellshocker.net/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/252743");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( get_kb_item( "ssh/force/pty" ) )
  exit( 0 );

if( ! bin = get_app_location( cpe:CPE, port:0 ) ) # Returns e.g. "/bin/bash" or "unknown" (if the location of the binary wasn't detected).
  exit( 0 );

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

if( bin == "unknown" )
  bash_cmd = "bash";
else if( bin =~ "^/.*bash$" )
  bash_cmd = bin;
else
  exit( 0 ); # Safeguard if something is broken in the bash detection

# echo 'env x="() { :;}; echo CVE-2014-6271 vulnerable" /bin/bash -c "echo this is a test"' | /bin/bash
cmd = "echo 'env x=" + '"' + '() { :;}; echo CVE-2014-6271 vulnerable" ' + bash_cmd + ' -c "echo this is a test"' + "' | " + bash_cmd;

result = ssh_cmd( socket:sock, cmd:cmd, nosh:TRUE );
close( sock );

if( "CVE-2014-6271 vulnerable" >< result && "echo CVE-2014-6271 vulnerable" >!< result ) {
  report = "Used command: " + cmd + '\n\nResult: ' + result;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );