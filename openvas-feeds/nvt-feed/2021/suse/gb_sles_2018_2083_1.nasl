# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2083.1");
  script_cve_id("CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2972", "CVE-2018-2973");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:42 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-24 18:35:17 +0000 (Tue, 24 Jul 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2083-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2083-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182083-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-10-openjdk' package(s) announced via the SUSE-SU-2018:2083-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for OpenJDK 10.0.2 fixes the following security issues:
- CVE-2018-2940: the libraries sub-component contained an easily
 exploitable vulnerability that allowed attackers to compromise Java SE
 or Java SE Embedded over the network, potentially gaining unauthorized
 read access to data that's accessible to the server. [bsc#1101645]
- CVE-2018-2952: the concurrency sub-component contained a difficult to
 exploit vulnerability that allowed attackers to compromise Java SE, Java
 SE Embedded,
 or JRockit over the network. This issue could have been abused to mount
 a partial denial-of-service attack on the server. [bsc#1101651]
- CVE-2018-2972: the security sub-component contained a difficult to
 exploit vulnerability that allowed attackers to compromise Java SE over
 the network, potentially gaining unauthorized access to critical data or
 complete access to all Java SE accessible data. [bsc#1101655)
- CVE-2018-2973: the JSSE sub-component contained a difficult to exploit
 vulnerability allowed attackers to compromise Java SE or Java SE Embedded
 over the network, potentially gaining the ability to create, delete or
 modify critical data or all Java SE, Java SE Embedded accessible data
 without authorization. [bsc#1101656]
Furthemore, the following bugs were fixed:
- Properly remove the existing alternative for java before reinstalling
 it. [bsc#1096420]
- idlj was moved to the *-devel package. [bsc#1096420]");

  script_tag(name:"affected", value:"'java-10-openjdk' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk", rpm:"java-10-openjdk~10.0.2.0~3.3.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-debuginfo", rpm:"java-10-openjdk-debuginfo~10.0.2.0~3.3.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-debugsource", rpm:"java-10-openjdk-debugsource~10.0.2.0~3.3.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-demo", rpm:"java-10-openjdk-demo~10.0.2.0~3.3.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-devel", rpm:"java-10-openjdk-devel~10.0.2.0~3.3.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-headless", rpm:"java-10-openjdk-headless~10.0.2.0~3.3.3", rls:"SLES15.0"))) {
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
