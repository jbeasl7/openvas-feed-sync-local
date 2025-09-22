# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844279");
  script_cve_id("CVE-2019-2894", "CVE-2019-2945", "CVE-2019-2949", "CVE-2019-2962", "CVE-2019-2964", "CVE-2019-2973", "CVE-2019-2975", "CVE-2019-2977", "CVE-2019-2978", "CVE-2019-2981", "CVE-2019-2983", "CVE-2019-2987", "CVE-2019-2988", "CVE-2019-2989", "CVE-2019-2992", "CVE-2019-2999");
  script_tag(name:"creation_date", value:"2019-12-18 03:01:35 +0000 (Wed, 18 Dec 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-22 14:54:00 +0000 (Tue, 22 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-4223-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|19\.04|19\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4223-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4223-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8, openjdk-lts' package(s) announced via the USN-4223-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan Jancar, Petr Svenda, and Vladimir Sedlacek discovered that a side-
channel vulnerability existed in the ECDSA implementation in OpenJDK. An
Attacker could use this to expose sensitive information. (CVE-2019-2894)

It was discovered that the Socket implementation in OpenJDK did not
properly restrict the creation of subclasses with a custom Socket
implementation. An attacker could use this to specially create a Java class
that could possibly bypass Java sandbox restrictions. (CVE-2019-2945)

Rob Hamm discovered that the Kerberos implementation in OpenJDK did not
properly handle proxy credentials. An attacker could possibly use this to
impersonate another user. (CVE-2019-2949)

It was discovered that a NULL pointer dereference existed in the font
handling implementation in OpenJDK. An attacker could use this to cause a
denial of service (application crash). (CVE-2019-2962)

It was discovered that the Concurrency subsystem in OpenJDK did not
properly bound stack consumption when compiling regular expressions. An
attacker could use this to cause a denial of service (application crash).
(CVE-2019-2964)

It was discovered that the JAXP subsystem in OpenJDK did not properly
handle XPath expressions in some situations. An attacker could use this to
cause a denial of service (application crash). (CVE-2019-2973,
CVE-2019-2981)

It was discovered that the Nashorn JavaScript subcomponent in OpenJDK did
not properly handle regular expressions in some situations. An attacker
could use this to cause a denial of service (application crash).
(CVE-2019-2975)

It was discovered that the String class in OpenJDK contained an out-of-
bounds access vulnerability. An attacker could use this to cause a denial
of service (application crash) or possibly expose sensitive information.
This issue only affected OpenJDK 11 in Ubuntu 18.04 LTS, Ubuntu 19.04,
and Ubuntu 19.10. (CVE-2019-2977)

It was discovered that the Jar URL handler in OpenJDK did not properly
handled nested Jar URLs in some situations. An attacker could use this to
cause a denial of service (application crash). (CVE-2019-2978)

It was discovered that the Serialization component of OpenJDK did not
properly handle deserialization of certain object attributes. An attacker
could use this to cause a denial of service (application crash).
(CVE-2019-2983)

It was discovered that the FreetypeFontScaler class in OpenJDK did not
properly validate dimensions of glyph bitmap images read from font files.
An attacker could specially craft a font file that could cause a denial of
service (application crash). (CVE-2019-2987)

It was discovered that a buffer overflow existed in the SunGraphics2D class
in OpenJDK. An attacker could possibly use this to cause a denial of
service (excessive memory consumption or application crash).
(CVE-2019-2988)

It was discovered that the Networking component in OpenJDK did not properly
handle certain responses ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openjdk-8, openjdk-lts' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04, Ubuntu 19.10.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u232-b09-0ubuntu1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u232-b09-0ubuntu1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u232-b09-0ubuntu1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm", ver:"8u232-b09-0ubuntu1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u232-b09-0ubuntu1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.5+10-0ubuntu1.1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.5+10-0ubuntu1.1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.5+10-0ubuntu1.1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.5+10-0ubuntu1.1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.5+10-0ubuntu1.1~19.04", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.5+10-0ubuntu1.1~19.04", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.5+10-0ubuntu1.1~19.04", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.5+10-0ubuntu1.1~19.04", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.5+10-0ubuntu1.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.5+10-0ubuntu1.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.5+10-0ubuntu1.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.5+10-0ubuntu1.1", rls:"UBUNTU19.10"))) {
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
