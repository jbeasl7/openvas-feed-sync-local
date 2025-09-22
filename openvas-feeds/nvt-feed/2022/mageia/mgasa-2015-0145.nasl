# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0145");
  script_cve_id("CVE-2014-3619");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0145)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0145");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0145.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2015-03/msg00031.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14049");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15473");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glusterfs' package(s) announced via the MGASA-2015-0145 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated glusterfs packages fix security vulnerability:

glusterfs was vulnerable to a fragment header infinite loop denial of service
attack (CVE-2014-3619).

Also, the glusterfsd SysV init script was failing to properly start the
service. This was fixed by replacing it with systemd unit files for the
service that work properly (mga#14049).");

  script_tag(name:"affected", value:"'glusterfs' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"glusterfs", rpm:"glusterfs~3.4.1~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-client", rpm:"glusterfs-client~3.4.1~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-common", rpm:"glusterfs-common~3.4.1~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-geo-replication", rpm:"glusterfs-geo-replication~3.4.1~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-server", rpm:"glusterfs-server~3.4.1~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glusterfs-devel", rpm:"lib64glusterfs-devel~3.4.1~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glusterfs0", rpm:"lib64glusterfs0~3.4.1~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglusterfs-devel", rpm:"libglusterfs-devel~3.4.1~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglusterfs0", rpm:"libglusterfs0~3.4.1~1.2.mga4", rls:"MAGEIA4"))) {
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
