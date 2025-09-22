# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100577");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-15 19:15:10 +0200 (Thu, 15 Apr 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0897");
  script_name("Oracle Java System Directory Server Multiple Remote Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("sun_dir_server_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("SunJavaDirServer/installed", "ldap/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39453");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-073/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-074/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-075/");
  script_xref(name:"URL", value:"http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuapr2010.html");

  script_tag(name:"solution", value:"Vendor updates are available. Please contact the vendor for more
  information.");

  script_tag(name:"summary", value:"Oracle Java System Directory Server is prone to multiple remote
  vulnerabilities.");

  script_tag(name:"impact", value:"These vulnerabilities can be exploited over the 'LDAP' and 'HTTP'
  protocols. Remote attackers can exploit these issues without authenticating.

  Successful exploits will allow attackers to exploit arbitrary code in
  the context of the vulnerable application or cause denial-of-service
  conditions.");

  script_tag(name:"affected", value:"These vulnerabilities affect the following supported versions:
  5.2, 6.0, 6.1, 6.2, 6.3, 6.3.1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("ldap.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ldap_get_port(default:389);

if(!version = get_kb_item("ldap/" + port + "/SunJavaDirServer"))
  exit(0);

if(!isnull(version)) {
  if(version_in_range(version:version, test_version:"6", test_version2:"6.3.1") ||
     version_is_equal(version:version, test_version:"5.2")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"See references");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
