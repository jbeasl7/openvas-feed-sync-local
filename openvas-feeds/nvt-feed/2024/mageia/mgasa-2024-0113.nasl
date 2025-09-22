# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0113");
  script_cve_id("CVE-2024-2357");
  script_tag(name:"creation_date", value:"2024-04-09 04:13:31 +0000 (Tue, 09 Apr 2024)");
  script_version("2024-04-09T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-04-09 05:05:38 +0000 (Tue, 09 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0113)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0113");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0113.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32996");
  script_xref(name:"URL", value:"https://libreswan.org/security/CVE-2024-2357/CVE-2024-2357.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreswan' package(s) announced via the MGASA-2024-0113 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Libreswan Project was notified of an issue causing libreswan to
restart under some IKEv2 retransmit scenarios when a connection is
configured to use PreSharedKeys (authby=secret) and the connection
cannot find a matching configured secret. When such a connection is
automatically added on startup using the auto= keyword, it can cause
repeated crashes leading to a Denial of Service. (CVE-2024-2357)");

  script_tag(name:"affected", value:"'libreswan' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"libreswan", rpm:"libreswan~4.14~1.mga9", rls:"MAGEIA9"))) {
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
