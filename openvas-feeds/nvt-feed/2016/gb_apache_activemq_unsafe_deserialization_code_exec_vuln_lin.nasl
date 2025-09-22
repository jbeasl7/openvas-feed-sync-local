# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809062");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-5254");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 17:41:00 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"creation_date", value:"2016-10-04 19:50:32 +0530 (Tue, 04 Oct 2016)");

  script_name("Apache ActiveMQ Unsafe deserialization Code Execution Vulnerability - Linux");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/activemq/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.data/CVE-2015-5254-announcement.txt");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to not restricting the
  classes that can be serialized in the broker.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code via a crafted serialized Java Message
  Service (JMS) ObjectMessage object.");

  script_tag(name:"affected", value:"Apache ActiveMQ Version 5.0 through 5.12.1 on Linux");

  script_tag(name:"solution", value:"Upgrade to Apache ActiveMQ Version 5.13.0 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! appVer = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_in_range( version:appVer, test_version:"5.0.0", test_version2:"5.12.1" ) ) {
  report = report_fixed_ver( installed_version:appVer, fixed_version:"5.13.0" );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
