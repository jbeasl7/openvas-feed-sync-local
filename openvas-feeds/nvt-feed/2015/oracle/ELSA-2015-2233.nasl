# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122783");
  script_cve_id("CVE-2014-8240", "CVE-2014-8241");
  script_tag(name:"creation_date", value:"2015-11-25 11:18:50 +0000 (Wed, 25 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-20 02:59:00 +0000 (Tue, 20 Dec 2016)");

  script_name("Oracle: Security Advisory (ELSA-2015-2233)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2233");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2233.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tigervnc' package(s) announced via the ELSA-2015-2233 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.3.1-3]
- Do not mention that display number is required in the file name
 Resolves: bz#1195266

[1.3.1-2]
- Resolves: bz#1248422
 CVE-2014-8240 CVE-2014-8241 tigervnc: various flaws

[1.3.1-1]
- Drop unnecessary patches
- Re-base to 1.3.1 (bug #1199453)
- Re-build against re-based xserver (bug #1194898)
- Check the return value from XShmAttach (bug #1072733)
- Add missing part of xserver114.patch (bug #1140603)
- Keep pointer in sync (bug #1100661)
- Make input device class global (bug #1119640)
- Add IPv6 support (bug #1162722)
- Set initial mode as preferred (bug #1181287)
- Do not mention that display number is required in the file name (bug #1195266)
- Enable Xinerama extension (bug #1199437)
- Specify full path for runuser command (bug #1208817)

[1.2.80-0.31.20130314svn5065]
- Rebuilt against xorg-x11-server to pick up ppc64le fix (bug #1140424).");

  script_tag(name:"affected", value:"'tigervnc' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.3.1~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-icons", rpm:"tigervnc-icons~1.3.1~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-license", rpm:"tigervnc-license~1.3.1~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server", rpm:"tigervnc-server~1.3.1~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-applet", rpm:"tigervnc-server-applet~1.3.1~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-minimal", rpm:"tigervnc-server-minimal~1.3.1~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-module", rpm:"tigervnc-server-module~1.3.1~3.el7", rls:"OracleLinux7"))) {
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
