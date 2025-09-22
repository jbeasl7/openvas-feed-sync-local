# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0295");
  script_cve_id("CVE-2023-7256", "CVE-2024-8006");
  script_tag(name:"creation_date", value:"2024-09-12 04:12:48 +0000 (Thu, 12 Sep 2024)");
  script_version("2024-09-20T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-09-20 05:05:37 +0000 (Fri, 20 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-19 17:46:03 +0000 (Thu, 19 Sep 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0295)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0295");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0295.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33537");
  script_xref(name:"URL", value:"https://lwn.net/Articles/988357/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpcap' package(s) announced via the MGASA-2024-0295 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In affected libpcap versions during the setup of a remote packet capture
the internal function sock_initaddress() calls getaddrinfo() and
possibly freeaddrinfo(), but does not clearly indicate to the caller
function whether freeaddrinfo() still remains to be called after the
function returns. This makes it possible in some scenarios that both the
function and its caller call freeaddrinfo() for the same allocated
memory block. (CVE-2023-7256)
Remote packet capture support is disabled by default in libpcap. When a
user builds libpcap with remote packet capture support enabled, one of
the functions that become available is pcap_findalldevs_ex(). One of the
function arguments can be a filesystem path, which normally means a
directory with input data files. When the specified path cannot be used
as a directory, the function receives NULL from opendir(), but does not
check the return value and passes the NULL value to readdir(), which
causes a NULL pointer derefence. (CVE-2024-8006)");

  script_tag(name:"affected", value:"'libpcap' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64pcap-devel", rpm:"lib64pcap-devel~1.10.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcap1", rpm:"lib64pcap1~1.10.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap", rpm:"libpcap~1.10.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap-devel", rpm:"libpcap-devel~1.10.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap-doc", rpm:"libpcap-doc~1.10.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap1", rpm:"libpcap1~1.10.5~1.mga9", rls:"MAGEIA9"))) {
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
