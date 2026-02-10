# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2026.037.02");
  script_cve_id("CVE-2025-68160", "CVE-2025-69418", "CVE-2025-69419", "CVE-2025-69420", "CVE-2025-69421", "CVE-2026-22795", "CVE-2026-22796");
  script_tag(name:"creation_date", value:"2026-02-09 04:45:23 +0000 (Mon, 09 Feb 2026)");
  script_version("2026-02-09T06:03:20+0000");
  script_tag(name:"last_modification", value:"2026-02-09 06:03:20 +0000 (Mon, 09 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-02 18:29:59 +0000 (Mon, 02 Feb 2026)");

  script_name("Slackware: Security Advisory (SSA:2026-037-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2026-037-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2026&m=slackware-security.432529");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-68160");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-69418");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-69419");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-69420");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-69421");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-22795");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-22796");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SSA:2026-037-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New openssl packages are available for Slackware 15.0 to fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/openssl-1.1.1ze-i586-1_slack15.0.txz: Upgraded.
 Apply patch to fix the following security issues:
 Fixed Heap out-of-bounds write in BIO_f_linebuffer on short writes.
 Fixed Unauthenticated/unencrypted trailing bytes with low-level OCB function
 calls.
 Fixed Out of bounds write in PKCS12_get_friendlyname() UTF-8 conversion.
 Fixed Missing ASN1_TYPE validation in TS_RESP_verify_response() function.
 Fixed NULL Pointer Dereference in PKCS12_item_decrypt_d2i_ex() function.
 Fixed Missing ASN1_TYPE validation in PKCS#12 parsing.
 Fixed ASN1_TYPE Type Confusion in the PKCS7_digest_from_attributes() function.
 These CVEs were fixed by the 1.1.1ze release that is only available to
 subscribers to OpenSSL's premium extended support. The patch was prepared
 by backporting from the OpenSSL-3.0 repo.
 Thanks to Ken Zalewski for the patch!
 For more information, see:
 [links moved to references]
 (* Security fix *)
patches/packages/openssl-solibs-1.1.1ze-i586-1_slack15.0.txz: Upgraded.
+--------------------------+");

  script_tag(name:"affected", value:"'openssl' package(s) on Slackware 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.1.1ze-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.1.1ze-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.1.1ze-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.1.1ze-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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
