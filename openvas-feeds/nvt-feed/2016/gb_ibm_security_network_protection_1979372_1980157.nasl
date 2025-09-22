# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:security_network_protection";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105747");
  script_version("2023-11-03T05:05:46+0000");
  script_name("IBM Security Network Protection Multiple Vulnerabilities");
  script_cve_id("CVE-2016-0787", "CVE-2015-8629", "CVE-2015-8631");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21980157");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979372");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MIT Kerberos could allow a remote authenticated attacker to obtain sensitive information, caused by a null termination in the xdr_nullstring() function. By sending specially-crafted data, an attacker could exploit this vulnerability to obtain sensitive information from the memory.

libssh2 could provide weaker than expected security, caused by a type confusion error during the SSHv2 handshake resulting in the generation of a reduced amount of random bits for Diffie-Hellman. An attacker could exploit this vulnerability using the truncated Diffie-Hellman secret to launch further attacks on the system.");
  script_tag(name:"solution", value:"Update to 5.3.1.9/5.3.2.3 or newer");
  script_tag(name:"summary", value:"IBM Security Network Protection is prone to multiple vulnerabilities.

1. IBM Security Network Protection uses Kerberos (krb5) to provide network authentication. The Kerberos (krb5) version that is shipped with IBM Security Network Protection contains multiple security vulnerabilities.
2. The libssh2 packages provide a library that implements the SSHv2 protocol. A security vulnerability has been discovered in libssh2 used with IBM Security Network Protection.");
  script_tag(name:"affected", value:"IBM Security Network Protection 5.3.1
IBM Security Network Protection 5.3.2");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-02 19:15:00 +0000 (Tue, 02 Feb 2021)");
  script_tag(name:"creation_date", value:"2016-06-01 15:30:38 +0200 (Wed, 01 Jun 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_ibm_security_network_protection_version.nasl");
  script_mandatory_keys("isnp/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version =~ "^5\.3\.1" )
  if( version_is_less( version:version, test_version:"5.3.1.9" ) ) fix = "5.3.1.9";

if( version =~ "^5\.3\.2" )
  if( version_is_less( version:version, test_version:"5.3.2.3" ) ) fix = "5.3.2.3";

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

