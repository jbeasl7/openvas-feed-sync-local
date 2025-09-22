# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0281.1");
  script_cve_id("CVE-2014-9221");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0281-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0281-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150281-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/856322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/897048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/897512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910491");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-February/001221.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan' package(s) announced via the SUSE-SU-2015:0281-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This strongswan update fixes the following security and non security issues.

- Disallow brainpool elliptic curve groups in fips mode (bnc#856322).
- Applied an upstream fix for a denial-of-service vulnerability,
 which can be triggered by an IKEv2 Key Exchange payload, that
 contains the Diffie-Hellman group 1025 (bsc#910491,CVE-2014-9221).
- Adjusted whilelist of approved algorithms in fips mode (bsc#856322).
- Updated strongswan-hmac package description (bsc#856322).
- Disabled explicit gpg validation, osc source_validator does it.
- Guarded fipscheck and hmac package in the spec file for >13.1.
- Added generation of fips hmac hash files using fipshmac utility
 and a _fipscheck script to verify binaries/libraries/plugings
 shipped in the strongswan-hmac package.
 With enabled fips in the kernel, the ipsec script will call it
 before any action or in a enforced/manual 'ipsec _fipscheck' call.
 Added config file to load openssl and kernel af-alg plugins, but
 not all the other modules which provide further/alternative algs.
 Applied a filter disallowing non-approved algorithms in fips mode.
 (fate#316931,bnc#856322).
- Fixed file list in the optional (disabled) strongswan-test package.
- Fixed build of the strongswan built-in integrity checksum library
 and enabled building it only on architectures tested to work.
- Fix to use bug number 897048 instead 856322 in last changes entry.
- Applied an upstream patch reverting to store algorithms in the
 registration order again as ordering them by identifier caused
 weaker algorithms to be proposed first by default (bsc#897512).");

  script_tag(name:"affected", value:"'strongswan' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~5.1.3~9.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-doc", rpm:"strongswan-doc~5.1.3~9.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-hmac", rpm:"strongswan-hmac~5.1.3~9.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec", rpm:"strongswan-ipsec~5.1.3~9.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0", rpm:"strongswan-libs0~5.1.3~9.2", rls:"SLES12.0"))) {
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
