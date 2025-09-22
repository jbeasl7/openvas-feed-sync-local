# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100512");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-03-02 12:58:40 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:P");
  script_name("XMail Insecure Temporary File Creation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl");
  script_mandatory_keys("smtp/xmail/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38427");
  script_xref(name:"URL", value:"http://www.xmailserver.org/ChangeLog.html#feb_25__2010_v_1_27");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"XMail creates temporary files in an insecure manner.");

  script_tag(name:"impact", value:"An attacker with local access could potentially exploit this issue to
  perform symbolic-link attacks, overwriting arbitrary files in the context of the affected application.

  Successfully mounting a symlink attack may allow the attacker to delete or corrupt sensitive files,
  which may result in a denial of service. Other attacks may also be possible.");

  script_tag(name:"affected", value:"Versions prior to XMail 1.27 are affected.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("version_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port(default:25);
banner = smtp_get_banner(port:port);
if(!banner)
  exit(0);

banner = tolower(banner);
if("xmail" >!< banner)
  exit(0);

version = eregmatch(pattern:"xmail ([0-9.]+)", string:banner);
if(!version[1])
  exit(0);

if(version_is_less(version:version[1], test_version:"1.27")) {
  report = report_fixed_ver(installed_version:version[1], fixed_version:"1.27");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
