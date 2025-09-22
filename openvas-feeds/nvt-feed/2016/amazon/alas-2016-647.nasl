# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120637");
  script_cve_id("CVE-2015-7575", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0475", "CVE-2016-0483", "CVE-2016-0494");
  script_tag(name:"creation_date", value:"2016-02-11 05:16:45 +0000 (Thu, 11 Feb 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:30:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-647)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-647");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-647.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk' package(s) announced via the ALAS-2016-647 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds write flaw was found in the JPEG image format decoder in the AWT component in OpenJDK. A specially crafted JPEG image could cause a Java application to crash or, possibly execute arbitrary code. An untrusted Java application or applet could use this flaw to bypass Java sandbox restrictions. (CVE-2016-0483)

A flaw was found in the way TLS 1.2 could use the MD5 hash function for signing ServerKeyExchange and Client Authentication packets during a TLS handshake. A man-in-the-middle attacker able to force a TLS connection to use the MD5 hash function could use this flaw to conduct collision attacks to impersonate a TLS server or an authenticated TLS client. (CVE-2015-7575)

Integer signedness issues were discovered in IndicRearrangementProcessor and IndicRearrangementProcessor2 in the ICU Layout Engine. A specially crafted font file could cause an application using ICU to parse untrusted fonts to crash and, possibly, execute arbitrary code. (CVE-2016-0494)

It was discovered that the password-based encryption (PBE) implementation in the Libraries component in OpenJDK used an incorrect key length. This could, in certain cases, lead to generation of keys that were weaker than expected. (CVE-2016-0475)

A flaw was found in the deserialization of the URL class in the Networking component of OpenJDK. Deserialization of the specially crafted data could result in creation of the URL object with an inconsistent state. An untrusted Java application or applet could use this flaw to bypass certain Java sandbox restrictions. (CVE-2016-0402)

It was discovered that the JAXP component in OpenJDK did not properly enforce the totalEntitySizeLimit limit. An attacker able to make a Java application process a specially crafted XML file could use this flaw to make the application consume an excessive amount of memory. (CVE-2016-0466)

It was discovered that the RMIConnector and RMIConnectionImpl classes in the JMX component of OpenJDK could log sensitive information such as user passwords in its debug log, possibly leading the exposure of the information. (CVE-2016-0448)");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk' package(s) on Amazon Linux.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-debuginfo", rpm:"java-1.8.0-openjdk-debuginfo~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.71~2.b15.8.amzn1", rls:"AMAZON"))) {
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
