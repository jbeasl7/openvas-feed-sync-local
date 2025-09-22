# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sun:java_web_start";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800127");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2008-11-05 13:21:04 +0100 (Wed, 05 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4910");
  script_name("Sun Java Web Start Remote Command Execution Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Gain a shell remotely");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Java/WebStart/Linux/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46119");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31916");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2008-10/0192.html");

  script_tag(name:"impact", value:"Successful exploitation allows remote code execution on the
  client machines.");

  script_tag(name:"affected", value:"Sun J2SE 6.0 Update 10 and earlier.");

  script_tag(name:"insight", value:"The flaw exists due to weakness in the BasicService showDocument method
  which does not validate the inputs appropriately. This can be exploited
  using a specially crafted Java Web Start application via file:\\ URL
  argument to the showDocument method.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"Sun Java Web Start is prone to a remote command execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:FALSE ) )
  exit( 0 );

ver = infos["version"];
loc = infos["location"];

if( version_is_less_equal( version:ver, test_version:"1.6.0.10" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"WillNotFix", install_path:loc );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
