# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2933.1");
  script_cve_id("CVE-2016-7586", "CVE-2016-7589", "CVE-2016-7592", "CVE-2016-7599", "CVE-2016-7623", "CVE-2016-7632", "CVE-2016-7635", "CVE-2016-7639", "CVE-2016-7641", "CVE-2016-7645", "CVE-2016-7652", "CVE-2016-7654", "CVE-2016-7656", "CVE-2017-2350", "CVE-2017-2354", "CVE-2017-2355", "CVE-2017-2356", "CVE-2017-2362", "CVE-2017-2363", "CVE-2017-2364", "CVE-2017-2365", "CVE-2017-2366", "CVE-2017-2369", "CVE-2017-2371", "CVE-2017-2373", "CVE-2017-2496", "CVE-2017-2510", "CVE-2017-2538", "CVE-2017-2539", "CVE-2017-7018", "CVE-2017-7030", "CVE-2017-7034", "CVE-2017-7037", "CVE-2017-7039", "CVE-2017-7046", "CVE-2017-7048", "CVE-2017-7055", "CVE-2017-7056", "CVE-2017-7061", "CVE-2017-7064");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-20 16:29:02 +0000 (Thu, 20 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2933-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2933-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172933-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050469");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-November/003374.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2017:2933-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 to version 2.18.0 fixes the following issues:

These security issues were fixed:

- CVE-2017-7039: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site (bsc#1050469).
- CVE-2017-7018: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site (bsc#1050469).
- CVE-2017-7030: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site (bsc#1050469).
- CVE-2017-7037: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site (bsc#1050469).
- CVE-2017-7034: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site (bsc#1050469).
- CVE-2017-7055: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site (bsc#1050469).
- CVE-2017-7056: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site (bsc#1050469).
- CVE-2017-7064: An issue was fixed that allowed remote attackers to bypass
 intended memory-read restrictions via a crafted app (bsc#1050469).
- CVE-2017-7061: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site (bsc#1050469).
- CVE-2017-7048: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site (bsc#1050469).
- CVE-2017-7046: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and
 application crash) via a crafted web site (bsc#1050469).
- CVE-2017-2538: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site (bsc#1045460)
- CVE-2017-2496: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site.
- CVE-2017-2539: An issue was fixed that allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and application
 crash) via a crafted web site.
- CVE-2017-2510: An issue was fixed that allowed remote ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.18.0~2.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.18.0~2.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.18.0~2.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.18.0~2.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.18.0~2.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.18.0~2.9.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.18.0~2.9.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.18.0~2.9.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.18.0~2.9.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.18.0~2.9.1", rls:"SLES12.0SP3"))) {
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
