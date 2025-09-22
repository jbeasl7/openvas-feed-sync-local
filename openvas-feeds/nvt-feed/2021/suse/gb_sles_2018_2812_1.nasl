# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2812.1");
  script_cve_id("CVE-2018-0732", "CVE-2018-12115");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:37 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-02 16:04:28 +0000 (Fri, 02 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2812-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2812-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182812-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs8' package(s) announced via the SUSE-SU-2018:2812-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs8 to version 8.11.4 fixes the following issues:

Security issues fixed:
CVE-2018-12115: Fixed an out-of-bounds memory write in Buffer that could
 be used to write to memory outside of a Buffer's memory space buffer
 (bsc#1105019)

Upgrade to OpenSSL 1.0.2p, which fixed:
 - CVE-2018-0732: Client denial-of-service due to large DH parameter
 (bsc#1097158)
 - ECDSA key extraction via local side-channel

Other changes made:
Recommend same major version npm package (bsc#1097748)

Fix parallel/test-tls-passphrase.js test to continue to function with
 older versions of OpenSSL library.");

  script_tag(name:"affected", value:"'nodejs8' package(s) on SUSE Linux Enterprise Module for Web Scripting 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs8", rpm:"nodejs8~8.11.4~3.8.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-debuginfo", rpm:"nodejs8-debuginfo~8.11.4~3.8.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-debugsource", rpm:"nodejs8-debugsource~8.11.4~3.8.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-devel", rpm:"nodejs8-devel~8.11.4~3.8.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-docs", rpm:"nodejs8-docs~8.11.4~3.8.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm8", rpm:"npm8~8.11.4~3.8.2", rls:"SLES15.0"))) {
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
