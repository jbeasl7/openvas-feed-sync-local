# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843491");
  script_cve_id("CVE-2018-2579", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2629", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2641", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678");
  script_tag(name:"creation_date", value:"2018-04-03 06:51:06 +0000 (Tue, 03 Apr 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-01 14:30:49 +0000 (Thu, 01 Feb 2018)");

  script_name("Ubuntu: Security Advisory (USN-3614-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3614-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3614-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-3614-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the cryptography
implementation in OpenJDK. An attacker could possibly use this to expose
sensitive information. (CVE-2018-2579)

It was discovered that the LDAP implementation in OpenJDK did not properly
encode login names. A remote attacker could possibly use this to expose
sensitive information. (CVE-2018-2588)

It was discovered that the DNS client implementation in OpenJDK did not
properly randomize source ports. A remote attacker could use this to spoof
responses to DNS queries made by Java applications. (CVE-2018-2599)

It was discovered that the Internationalization component of OpenJDK did
not restrict search paths when loading resource bundle classes. A local
attacker could use this to trick a user into running malicious code.
(CVE-2018-2602)

It was discovered that OpenJDK did not properly restrict memory allocations
when parsing DER input. A remote attacker could possibly use this to cause
a denial of service. (CVE-2018-2603)

It was discovered that the Java Cryptography Extension (JCE) implementation
in OpenJDK in some situations did not guarantee sufficient strength of keys
during key agreement. An attacker could use this to expose sensitive
information. (CVE-2018-2618)

It was discovered that the Java GSS implementation in OpenJDK in some
situations did not properly handle GSS contexts in the native GSS library.
An attacker could possibly use this to access unauthorized resources.
(CVE-2018-2629)

It was discovered that the LDAP implementation in OpenJDK did not properly
handle LDAP referrals in some situations. An attacker could possibly use
this to expose sensitive information or gain unauthorized privileges.
(CVE-2018-2633)

It was discovered that the Java GSS implementation in OpenJDK in some
situations did not properly apply subject credentials. An attacker could
possibly use this to expose sensitive information or gain access to
unauthorized resources. (CVE-2018-2634)

It was discovered that the Java Management Extensions (JMX) component of
OpenJDK did not properly apply deserialization filters in some situations.
An attacker could use this to bypass deserialization restrictions.
(CVE-2018-2637)

It was discovered that a use-after-free vulnerability existed in the AWT
component of OpenJDK when loading the GTK library. An attacker could
possibly use this to execute arbitrary code and escape Java sandbox
restrictions. (CVE-2018-2641)

It was discovered that in some situations OpenJDK did not properly validate
objects when performing deserialization. An attacker could use this to
cause a denial of service (application crash or excessive memory
consumption). (CVE-2018-2663)

It was discovered that the AWT component of OpenJDK did not properly
restrict the amount of memory allocated when deserializing some objects. An
attacker could use this to cause a denial of service (excessive memory
consumption). ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u171-2.6.13-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jdk", ver:"7u171-2.6.13-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u171-2.6.13-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u171-2.6.13-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u171-2.6.13-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u171-2.6.13-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
