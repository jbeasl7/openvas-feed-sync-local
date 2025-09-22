# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntop:nbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809083");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-11-03 18:01:01 +0530 (Thu, 03 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("NBOX Multiple Vulnerabilities");

  script_tag(name:"summary", value:"NBOX is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insufficient validation of user supplied input via parameters
    'cmd', 'interface', 'dir', 'script' and 'act_cron' to files
    'write_conf_users.cgi', 'rrd_net_graph.cgi', 'pcap_upload.cgi',
    'sudowrapper.cgi', 'do_mergecap.cgi' and 'do_crontab.cgi'.

  - A cross-site request forgery vulnerability in 'do_factory_reset.cgi' script.

  - Default login credential nbox:nbox.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass authentication, execute arbitrary commands and to do
  machine reset.");

  script_tag(name:"affected", value:"NBOX version 2.3 through 2.5");

  script_tag(name:"solution", value:"Patches are available to fix these vulnerabilities, please contact the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ntop.org/support/misc/security/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40201");
  script_xref(name:"URL", value:"http://carnal0wnage.attackresearch.com/2016/08/got-any-rces.html");
  script_xref(name:"URL", value:"https://github.com/javuto/nbox-pwnage/issues/1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nbox_remote_detect.nasl");
  script_mandatory_keys("nBox/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"2.3", test_version2:"2.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See Vendor");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
