# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0069");
  script_cve_id("CVE-2020-36518", "CVE-2022-42003", "CVE-2022-42004");
  script_tag(name:"creation_date", value:"2024-03-18 04:11:54 +0000 (Mon, 18 Mar 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-04 18:56:31 +0000 (Tue, 04 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2024-0069)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0069");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0069.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2023:2312");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30368");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3IQ2OJSME4FMTGEF2CROURE4WDT3DEVB/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WTX6HAJ7KVGVZQ6APMA35RM7R7BKVSMB/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-May/011022.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-November/012934.html");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2990");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3207");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5283");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jackson-databind' package(s) announced via the MGASA-2024-0069 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"jackson-databind before 2.13.0 allows a Java StackOverflow exception and
denial of service via a large depth of nested objects. (CVE-2020-36518)
In FasterXML jackson-databind before versions 2.13.4.1 and 2.12.17.1,
resource exhaustion can occur because of a lack of a check in primitive
value deserializers to avoid deep wrapper array nesting, when the
UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled. (CVE-2022-42003)
In FasterXML jackson-databind before 2.13.4, resource exhaustion can
occur because of a lack of a check in
BeanDeserializer._deserializeFromArray to prevent use of deeply nested
arrays. An application is vulnerable only with certain customized
choices for deserialization. (CVE-2022-42004)");

  script_tag(name:"affected", value:"'jackson-databind' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind", rpm:"jackson-databind~2.11.4~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind-javadoc", rpm:"jackson-databind-javadoc~2.11.4~2.1.mga9", rls:"MAGEIA9"))) {
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
