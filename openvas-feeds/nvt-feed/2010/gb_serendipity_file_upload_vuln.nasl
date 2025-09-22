# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:s9y:serendipity";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901091");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-01-04 15:26:56 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4412");
  script_name("Serendipity File Extension Processing Arbitrary File Upload Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37830");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54985");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3626");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/12/21/1");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("serendipity_detect.nasl");
  script_mandatory_keys("Serendipity/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to upload PHP scripts and execute
  arbitrary commands on a web server with a specific configuration.");
  script_tag(name:"affected", value:"Serendipity version prior to 1.5 on all platforms.");
  script_tag(name:"insight", value:"The flaw is due to an input validation error in the file upload functionality
  when processing a file with a filename containing multiple file extensions.");
  script_tag(name:"solution", value:"Upgrade to Serendipity version 1.5 or later.");
  script_tag(name:"summary", value:"Serendipity is prone to arbitrary file upload vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:ver, test_version:"1.5")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"1.5");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
