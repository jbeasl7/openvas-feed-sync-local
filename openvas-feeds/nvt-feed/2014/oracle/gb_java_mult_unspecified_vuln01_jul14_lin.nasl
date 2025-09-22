# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108410");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2014-4244", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4252",
                "CVE-2014-4268", "CVE-2014-4218", "CVE-2014-4216", "CVE-2014-4209");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-07-24 10:09:17 +0530 (Thu, 24 Jul 2014)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 (Jul 2014) - Linux");

  script_tag(name:"summary", value:"Oracle Java SE JRE is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple unspecified flaws exist:

  - An error in the JMX subcomponent related to
share/classes/com/sun/jmx/remote/security/SubjectDelegator.java

  - An error related to the Hotspot subcomponent in
share/vm/classfile/classFileParser.hpp

  - An error in the Libraries subcomponent related to
share/classes/java/lang/reflect/Proxy.java and handling of interfaces passed to
proxy methods.

  - An error within the Swing subcomponent related to missing access restrictions
imposed by the file choosers.

  - An error in the Security subcomponent related to
share/classes/java/security/Provider.java and instantiation of security services
with non-public constructors.

  - An error in the Diffie-Hellman key agreement within the Security subcomponent
related to 'validateDHPublicKey' function in
share/classes/sun/security/util/KeyUtil.java

  - An error in Libraries subcomponent within 'AtomicReferenceFieldUpdaterImpl'
function in /java/util/concurrent/atomic/AtomicReferenceFieldUpdater.java

  - An error in the Security subcomponent related to
share/classes/sun/security/rsa/RSACore.java and RSA 'blinding'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to update,
  insert, or delete certain data, execute arbitrary code, conduct a denial of
  service and disclosure of potentially sensitive information.");

  script_tag(name:"affected", value:"Oracle Java SE 5 update 65 and prior, 6 update 75 and prior, 7 update 60 and
  prior, and 8 update 5 and prior on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59501");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68562");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68583");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68599");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68615");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68624");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68636");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68639");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68642");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1030577");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:oracle:jdk", "cpe:/a:sun:jre", "cpe:/a:sun:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.[5-8]") {
  if(version_in_range(version:vers, test_version:"1.5.0", test_version2:"1.5.0.65")||
     version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.75")||
     version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.60")||
     version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.5")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
