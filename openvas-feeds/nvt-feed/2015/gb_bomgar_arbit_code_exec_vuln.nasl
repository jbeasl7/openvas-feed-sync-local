# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

CPE = "cpe:/a:bomgar:remote_support";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805800");
  script_version("2024-07-03T06:48:05+0000");
  script_cve_id("CVE-2015-0935");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-06-22 17:33:34 +0530 (Mon, 22 Jun 2015)");
  script_name("Bomgar Remote Support < 15.1.1 Arbitrary Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bomgar_remote_support_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_beyondtrust_remote_support_http_detect.nasl");
  script_mandatory_keys("bomgar/remote_support/detected");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/978652");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74460");

  script_tag(name:"summary", value:"Bomgar Remote Support is prone to an arbitrary code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the portal application that is triggered when
  deserializing untrusted input using the unserialize() function.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to inject
  PHP objects and execute arbitrary code.");

  script_tag(name:"affected", value:"Bomgar Remote Support version before 15.1.1.");

  script_tag(name:"solution", value:"Update to version 15.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"15.1.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"15.1.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
