# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843803");
  script_cve_id("CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3150", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3183", "CVE-2018-3214");
  script_tag(name:"creation_date", value:"2018-11-01 05:05:33 +0000 (Thu, 01 Nov 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-23 12:05:24 +0000 (Tue, 23 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-3804-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|18\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3804-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3804-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8, openjdk-lts' package(s) announced via the USN-3804-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Security component of OpenJDK did not properly
ensure that manifest elements were signed before use. An attacker could
possibly use this to specially construct an untrusted Java application or
applet that could escape sandbox restrictions. (CVE-2018-3136)

Artem Smotrakov discovered that the HTTP client redirection handler
implementation in OpenJDK did not clear potentially sensitive information
in HTTP headers when following redirections to different hosts. An attacker
could use this to expose sensitive information. (CVE-2018-3139)

It was discovered that the Java Naming and Directory Interface (JNDI)
implementation in OpenJDK did not properly enforce restrictions specified
by system properties in some situations. An attacker could potentially use
this to execute arbitrary code. (CVE-2018-3149)

It was discovered that the Utility component of OpenJDK did not properly
ensure all attributes in a JAR were signed before use. An attacker could
use this to specially construct an untrusted Java application or applet
that could escape sandbox restrictions. This issue only affected Ubuntu
18.04 LTS and Ubuntu 18.10. (CVE-2018-3150)

It was discovered that the Hotspot component of OpenJDK did not properly
perform access checks in certain cases when performing field link
resolution. An attacker could use this to specially construct an untrusted
Java application or applet that could escape sandbox restrictions.
(CVE-2018-3169)

Felix Dorre discovered that the Java Secure Socket Extension (JSSE)
implementation in OpenJDK did not ensure that the same endpoint
identification algorithm was used during TLS session resumption as during
initial session setup. An attacker could use this to expose sensitive
information. (CVE-2018-3180)

Krzysztof Szafranski discovered that the Scripting component did not
properly restrict access to the scripting engine in some situations. An
attacker could use this to specially construct an untrusted Java
application or applet that could escape sandbox restrictions.
(CVE-2018-3183)

Tobias Ospelt discovered that the Resource Interchange File Format (RIFF)
reader implementation in OpenJDK contained an infinite loop. An attacker
could use this to cause a denial of service. This issue only affected
Ubuntu 16.04 LTS. (CVE-2018-3214)");

  script_tag(name:"affected", value:"'openjdk-8, openjdk-lts' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u181-b13-1ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u181-b13-1ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u181-b13-1ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm", ver:"8u181-b13-1ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"10.0.2+13-1ubuntu0.18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"10.0.2+13-1ubuntu0.18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"10.0.2+13-1ubuntu0.18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.1+13-2ubuntu1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.1+13-2ubuntu1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.1+13-2ubuntu1", rls:"UBUNTU18.10"))) {
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
