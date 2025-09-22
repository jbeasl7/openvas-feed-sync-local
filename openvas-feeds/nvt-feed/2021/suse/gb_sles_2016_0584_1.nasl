# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0584.1");
  script_cve_id("CVE-2015-7575", "CVE-2016-1523", "CVE-2016-1930", "CVE-2016-1935", "CVE-2016-1938");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:08 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-09 19:26:10 +0000 (Tue, 09 Feb 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0584-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0584-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160584-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967087");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-February/001894.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, MozillaFirefox-branding-SLED, MozillaFirefox-branding-SLES-for-VMware, mozilla-nss' package(s) announced via the SUSE-SU-2016:0584-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox, MozillaFirefox-branding-SLE, mozilla-nss fixes the following issues:

Firefox 38.6.1 ESR (bsc#967087)

The following vulnerabilities were fixed:

- CVE-2016-1523: Fixed denial of service in Graphite 2 library (MFSA 2016-14/bmo#1246093)

Firefox 38.6.0 ESR + Mozilla NSS 3.20.2. (bsc#963520)

The following vulnerabilities were fixed:

- CVE-2016-1930: Memory safety bugs fixed in Firefox ESR 38.6 (bsc#963632)
- CVE-2016-1935: Buffer overflow in WebGL after out of memory allocation (bsc#963635)
- CVE-2016-1938: Calculations with mp_div and mp_exptmod in Network Security Services (NSS) canproduce wrong results (bsc#963731)
- CVE-2015-7575: MD5 signatures accepted within TLS 1.2 ServerKeyExchange in server signature (bsc#959888)

The following improvements were added:

- bsc#954447: Mozilla NSS now supports a number of new DHE ciphersuites
- Tracking protection is now enabled by default");

  script_tag(name:"affected", value:"'MozillaFirefox, MozillaFirefox-branding-SLED, MozillaFirefox-branding-SLES-for-VMware, mozilla-nss' package(s) on SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~38.6.1esr~33.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~38~15.58", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~38.6.1esr~33.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.20.2~17.5", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.20.2~17.5", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.20.2~17.5", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.20.2~17.5", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.20.2~17.5", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.20.2~17.5", rls:"SLES11.0SP2"))) {
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
