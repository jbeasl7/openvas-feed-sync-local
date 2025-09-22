# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123615");
  script_cve_id("CVE-2013-1872", "CVE-2013-1993");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:18 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0897)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0897");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0897.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mesa' package(s) announced via the ELSA-2013-0897 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[9.0-0.8.3]
- CVE-2013-1872: Updated patch with testing from upstream (#963063)

[9.0-0.8.2]
- CVE-2013-1872: Updated patch from upstream (#963063)

[9.0-0.8.1]
- CVE-2013-1872: Updated patch (#963063)

[9.0-0.8]
- CVE-2013-1872: memory corruption oob read/write on intel (#963063)
- CVE-2013-1993: integer overflows in protocol handling (#961613)");

  script_tag(name:"affected", value:"'mesa' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"glx-utils", rpm:"glx-utils~9.0~0.8.el6_4.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa", rpm:"mesa~9.0~0.8.el6_4.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-demos", rpm:"mesa-demos~9.0~0.8.el6_4.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-dri-drivers", rpm:"mesa-dri-drivers~9.0~0.8.el6_4.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-dri-filesystem", rpm:"mesa-dri-filesystem~9.0~0.8.el6_4.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libGL", rpm:"mesa-libGL~9.0~0.8.el6_4.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libGL-devel", rpm:"mesa-libGL-devel~9.0~0.8.el6_4.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libGLU", rpm:"mesa-libGLU~9.0~0.8.el6_4.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libGLU-devel", rpm:"mesa-libGLU-devel~9.0~0.8.el6_4.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libOSMesa", rpm:"mesa-libOSMesa~9.0~0.8.el6_4.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libOSMesa-devel", rpm:"mesa-libOSMesa-devel~9.0~0.8.el6_4.3", rls:"OracleLinux6"))) {
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
