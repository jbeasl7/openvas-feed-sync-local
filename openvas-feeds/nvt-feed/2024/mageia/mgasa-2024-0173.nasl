# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0173");
  script_cve_id("CVE-2024-33599", "CVE-2024-33600", "CVE-2024-33601", "CVE-2024-33602");
  script_tag(name:"creation_date", value:"2024-05-13 04:11:30 +0000 (Mon, 13 May 2024)");
  script_version("2024-05-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-05-13 05:05:46 +0000 (Mon, 13 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0173)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0173");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0173.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33185");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the MGASA-2024-0173 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stack-based buffer overflow in netgroup cache: If the Name Service Cache
Daemon's (nscd) fixed size cache is exhausted by client requests then a
subsequent client request for netgroup data may result in a stack-based
buffer overflow. (CVE-2024-33599)
Null pointer crashes after notfound response: If the Name Service Cache
Daemon's (nscd) cache fails to add a not-found netgroup response to the
cache, the client request can result in a null pointer dereference.
(CVE-2024-33600)
Netgroup cache may terminate daemon on memory allocation failure: The
Name Service Cache Daemon's (nscd) netgroup cache uses xmalloc or
xrealloc and these functions may terminate the process due to a memory
allocation failure resulting in a denial of service to the clients.
(CVE-2024-33601)
Netgroup cache assumes NSS callback uses in-buffer strings: The Name
Service Cache Daemon's (nscd) netgroup cache can corrupt memory when the
NSS callback does not store all strings in the provided buffer.
(CVE-2024-33602)");

  script_tag(name:"affected", value:"'glibc' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.36~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.36~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.36~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.36~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.36~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.36~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.36~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.36~54.mga9", rls:"MAGEIA9"))) {
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
