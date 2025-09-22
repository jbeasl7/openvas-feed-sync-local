# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123751");
  script_cve_id("CVE-2009-2473");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:04 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0131)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0131");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0131.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-vfs2' package(s) announced via the ELSA-2013-0131 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.16.2-10.el5]
- Prevent trash applet crashing (#848822)

[2.16.2-9.el5]
- Prevent deleting items linking out of the trash (#586015)
- Do not stat every file on an ClearCase mvfs filesystem (#822817)
- Do not silently skip directory having no read permission during copy (#772307)
- Allow trashing symlink to filesystem root that does not support trashing (#621394)
- CVE-2009-2473 gnome-vfs2 embedded neon: billion laughs DoS attack (#540548)");

  script_tag(name:"affected", value:"'gnome-vfs2' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"gnome-vfs2", rpm:"gnome-vfs2~2.16.2~10.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-vfs2-devel", rpm:"gnome-vfs2-devel~2.16.2~10.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-vfs2-smb", rpm:"gnome-vfs2-smb~2.16.2~10.el5", rls:"OracleLinux5"))) {
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
