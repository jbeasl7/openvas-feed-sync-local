# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1749");
  script_cve_id("CVE-2019-12795");
  script_tag(name:"creation_date", value:"2020-01-23 12:21:37 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-12 15:56:56 +0000 (Wed, 12 Jun 2019)");

  script_name("Huawei EulerOS: Security Advisory for gvfs (EulerOS-SA-2019-1749)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1749");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1749");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'gvfs' package(s) announced via the EulerOS-SA-2019-1749 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"daemon/gvfsdaemon.c in gvfsd from GNOME gvfs before 1.38.3, 1.40.x before 1.40.2, and 1.41.x before 1.41.3 opened a private D-Bus server socket without configuring an authorization rule. A local attacker could connect to this server socket and issue D-Bus method calls. (Note that the server socket only accepts a single connection, so the attacker would have to discover the server and connect to the socket before its owner does.)(CVE-2019-12795)");

  script_tag(name:"affected", value:"'gvfs' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"gvfs", rpm:"gvfs~1.22.4~6.h1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-afc", rpm:"gvfs-afc~1.22.4~6.h1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-afp", rpm:"gvfs-afp~1.22.4~6.h1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-archive", rpm:"gvfs-archive~1.22.4~6.h1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-devel", rpm:"gvfs-devel~1.22.4~6.h1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-fuse", rpm:"gvfs-fuse~1.22.4~6.h1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-goa", rpm:"gvfs-goa~1.22.4~6.h1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-gphoto2", rpm:"gvfs-gphoto2~1.22.4~6.h1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-mtp", rpm:"gvfs-mtp~1.22.4~6.h1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-smb", rpm:"gvfs-smb~1.22.4~6.h1", rls:"EULEROS-2.0SP2"))) {
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
