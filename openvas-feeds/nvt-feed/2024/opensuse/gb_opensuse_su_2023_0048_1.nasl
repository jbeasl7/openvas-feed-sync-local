# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833891");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-25563", "CVE-2023-25564", "CVE-2023-25565", "CVE-2023-25566", "CVE-2023-25567");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-22 18:39:17 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:05:22 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for gssntlmssp (openSUSE-SU-2023:0048-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0048-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WXCOTOTL4ZIZB65QEGM65YZZILOED4A3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gssntlmssp'
  package(s) announced via the openSUSE-SU-2023:0048-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gssntlmssp fixes the following issues:

     Update to version 1.2.0

  * Implement gss_set_cred_option.

  * Allow to gss_wrap even if NEGOTIATE_SEAL is not negotiated.

  * Move HMAC code to OpenSSL EVP API.

  * Fix crash bug when acceptor credentials are NULL.

  * Translations update from Fedora Weblate.

     Fix security issues:

  * CVE-2023-25563 (boo#1208278): multiple out-of-bounds read when decoding
       NTLM fields.

  * CVE-2023-25564 (boo#1208279): memory corruption when decoding UTF16
       strings.

  * CVE-2023-25565 (boo#1208280): incorrect free when decoding target
       information.

  * CVE-2023-25566 (boo#1208281): memory leak when parsing usernames.

  * CVE-2023-25567 (boo#1208282): out-of-bounds read when decoding target
       information.

     Update to version 1.1

  * various build fixes and better compatibility when a MIC is requested.

     Update to version 1.0

  * Fix test_gssapi_rfc5587.

  * Actually run tests with make check.

  * Add two tests around NTLMSSP_NEGOTIATE_LMKEY.

  * Refine LM compatibility level logic.

  * Refactor the gssntlm_required_security function.

  * Implement reading LM/NT hashes.

  * Add test for smpasswd-like user files.

  * Return confidentiality status.

  * Fix segfault in sign/seal functions.

  * Fix dummy signature generation.

  * Use UCS16LE instead of UCS-2LE.

  * Provide a zero lm key if the password is too long.

  * Completely omit CBs AV pairs when no CB provided.

  * Change license to the more permissive ISC.

  * Do not require cached users with winbind.

  * Add ability to pass keyfile via cred store.

  * Remove unused parts of Makefile.am.

  * Move attribute names to allocated strings.

  * Adjust serialization for name attributes.

  * Fix crash in acquiring credentials.

  * Fix fallback to external_creds interface.

  * Introduce parse_user_name() function.

  * Add test for parse_user_name.

  * Change how we assemble user names in ASC.

  * Use thread local storage for winbind context.

  * Make per thread winbind context optional.

  * Fixed memleak of usr_cred.

  * Support get_sids request via name attributes.

  * Fixed memory leaks found by valgrind.

  - Update to version 0.9

  * add support for getting session key.

  * Add gss_inquire_attrs_for_mech().

  * Return actual data for RFC5587 API.

  * Add new Windows version flags.

  * Add Key exchange also when wanting integrity only.

  * Drop support for GSS_C_MA_NOT_DFLT_MECH.");

  script_tag(name:"affected", value:"'gssntlmssp' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"gssntlmssp", rpm:"gssntlmssp~1.2.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gssntlmssp-devel", rpm:"gssntlmssp-devel~1.2.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gssntlmssp", rpm:"gssntlmssp~1.2.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gssntlmssp-devel", rpm:"gssntlmssp-devel~1.2.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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