# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843522");
  script_cve_id("CVE-2018-2783", "CVE-2018-2790", "CVE-2018-2794", "CVE-2018-2795", "CVE-2018-2796", "CVE-2018-2797", "CVE-2018-2798", "CVE-2018-2799", "CVE-2018-2800", "CVE-2018-2814", "CVE-2018-2815");
  script_tag(name:"creation_date", value:"2018-05-12 03:49:47 +0000 (Sat, 12 May 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-27 13:47:18 +0000 (Fri, 27 Apr 2018)");

  script_name("Ubuntu: Security Advisory (USN-3644-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|17\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3644-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3644-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8' package(s) announced via the USN-3644-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Security component of OpenJDK did not
correctly perform merging of multiple sections for the same file listed
in JAR archive file manifests. An attacker could possibly use this to
modify attributes in a manifest without invalidating the signature.
(CVE-2018-2790)

Francesco Palmarini, Marco Squarcina, Mauro Tempesta, and Riccardo Focardi
discovered that the Security component of OpenJDK did not restrict which
classes could be used when deserializing keys from the JCEKS key stores. An
attacker could use this to specially craft a JCEKS key store to execute
arbitrary code. (CVE-2018-2794)

It was discovered that the Security component of OpenJDK in some situations
did not properly limit the amount of memory allocated when performing
deserialization. An attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2018-2795)

It was discovered that the Concurrency component of OpenJDK in some
situations did not properly limit the amount of memory allocated when
performing deserialization. An attacker could use this to cause a
denial of service (memory exhaustion). (CVE-2018-2796)

It was discovered that the JMX component of OpenJDK in some situations did
not properly limit the amount of memory allocated when performing
deserialization. An attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2018-2797)

It was discovered that the AWT component of OpenJDK in some situations did
not properly limit the amount of memory allocated when performing
deserialization. An attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2018-2798)

It was discovered that the JAXP component of OpenJDK in some situations did
not properly limit the amount of memory allocated when performing
deserialization. An attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2018-2799)

Moritz Bechler discovered that the RMI component of OpenJDK enabled HTTP
transport for RMI servers by default. A remote attacker could use this to
gain access to restricted services. (CVE-2018-2800)

It was discovered that a vulnerability existed in the Hotspot component of
OpenJDK affecting confidentiality, data integrity, and availability. An
attacker could use this to specially craft an Java application that caused
a denial of service or bypassed sandbox restrictions. (CVE-2018-2814)

Apostolos Giannakidis discovered that the Serialization component
of OpenJDK did not properly bound memory allocations in some
situations. An attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2018-2815)

David Benjamin discovered a vulnerability in the Security component
of OpenJDK related to data integrity and confidentiality. A remote
attacker could possibly use this to expose sensitive information.
(CVE-2018-2783)");

  script_tag(name:"affected", value:"'openjdk-8' package(s) on Ubuntu 16.04, Ubuntu 17.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u171-b11-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u171-b11-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm", ver:"8u171-b11-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u171-b11-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u171-b11-0ubuntu0.17.10.1", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u171-b11-0ubuntu0.17.10.1", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u171-b11-0ubuntu0.17.10.1", rls:"UBUNTU17.10"))) {
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
