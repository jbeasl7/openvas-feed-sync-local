# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801920");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-0018");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_name("OpenVAS Manager OMP Request Handling Command Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65011");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45987");
  script_xref(name:"URL", value:"http://www.openvas.org/OVSA20110118.html");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16086/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0208");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary commands
  with the privileges of the OpenVAS Manager (typically root).");

  script_tag(name:"affected", value:"OpenVAS Manager versions prior to 1.0.4 and prior to 2.0.2.");

  script_tag(name:"insight", value:"The flaw is due to an input validation error in the 'email()' function
  in 'manage_sql.c' while processing OMP (OpenVAS Management Protocol) requests
  sent by authenticated users of the GSA (Greenbone Security Assistant) web application.");

  script_tag(name:"summary", value:"OpenVAS Manager is prone to a command injection vulnerability.");

  script_tag(name:"solution", value:"Apply the patch or update to OpenVAS Manager 1.0.4, 2.0.2 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"openvasmd", sock:sock);
foreach binName(paths) {

  binName = chomp(binName);
  if(!binName)
    continue;

  omVer = ssh_get_bin_version(full_prog_name:binName, sock:sock, version_argv:"--version", ver_pattern:"OpenVAS Manager.*");

  if(!isnull(omVer[0])) {
    omVer = eregmatch(pattern:"OpenVAS Manager ([0-9]\.[0-9]\.[0-9]+).?(rc[0-9]+)?", string:omVer[0]);
    if(!isnull(omVer[1]) && !isnull(omVer[2])) {
      ver = omVer[1] + "." + omVer[2];
    }
    else if(!isnull(omVer[1]) && isnull(omVer[2])) {
      ver = omVer[1];
    }
  }

  if(ver) {
    if(version_in_range(version:ver, test_version:"1.0", test_version2:"1.0.3") ||
       version_in_range(version:ver, test_version:"2.0", test_version2:"2.0.1")) {
      report = report_fixed_ver(installed_version:ver, fixed_version:"1.0.4/2.0.2");
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);
