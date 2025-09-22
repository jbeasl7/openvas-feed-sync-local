# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902509");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_cve_id("CVE-2011-1690");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("RT (Request Tracker) Unspecified Security Bypass Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("rt_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RequestTracker/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to trick users into
  sending credentials to an arbitrary server via unspecified vectors.");

  script_tag(name:"affected", value:"RT (Request Tracker) versions 3.6.0 through 3.6.10 and 3.8.0 through 3.8.8.");

  script_tag(name:"insight", value:"The flaw is caused by an unspecified error and can be exploited to trick
  a user into sending authentication credentials to an untrusted 3rd party server.");

  script_tag(name:"solution", value:"Upgrade to RT (Request Tracker) version 3.8.10 or 3.6.11.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Request Tracker is prone to unspecified security bypass vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44189");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47383");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66794");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=696795");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);
if(vers = get_version_from_kb(port:port,app:"rt_tracker"))
{
  if(version_in_range(version:vers, test_version:"3.8.0", test_version2:"3.8.8") ||
     version_in_range(version:vers, test_version:"3.6.0", test_version2:"3.6.10")){
    security_message(port:port);
  }
}
