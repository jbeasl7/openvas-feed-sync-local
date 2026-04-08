# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20934.1");
  script_cve_id("CVE-2026-32597");
  script_tag(name:"creation_date", value:"2026-04-03 04:47:54 +0000 (Fri, 03 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20934-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20934-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620934-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259616");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045218.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-PyJWT' package(s) announced via the SUSE-SU-2026:20934-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-PyJWT fixes the following issue:

Update to PyJWT 2.12.1:

- CVE-2026-32597: PyJWT accepts unknown `crit` header extensions (bsc#1259616).

Changelog:

Update to 2.12.1:

 - Add missing typing_extensions dependency for Python < 3.11 in
 #1150

Update to 2.12.0:

 - Annotate PyJWKSet.keys for pyright by @tamird in #1134
 - Close HTTPError response to prevent ResourceWarning on
 Python 3.14 by @veeceey in #1133
 - Do not keep algorithms dict in PyJWK instances by @akx in
 #1143
 - Use PyJWK algorithm when encoding without explicit
 algorithm in #1148
 - Docs: Add PyJWKClient API reference and document the
 two-tier caching system (JWK Set cache and signing key LRU
 cache).

Update to 2.11.0:

 - Enforce ECDSA curve validation per RFC 7518 Section 3.4.
 - Fix build system warnings by @kurtmckee in #1105
 - Validate key against allowed types for Algorithm family in
 #964
 - Add iterator for JWKSet in #1041
 - Validate iss claim is a string during encoding and decoding
 by @pachewise in #1040
 - Improve typing/logic for options in decode, decode_complete
 by @pachewise in #1045
 - Declare float supported type for lifespan and timeout by
 @nikitagashkov in #1068
 - Fix SyntaxWarnings/DeprecationWarnings caused by invalid
 escape sequences by @kurtmckee in #1103
 - Development: Build a shared wheel once to speed up test
 suite setup times by @kurtmckee in #1114
 - Development: Test type annotations across all supported
 Python versions, increase the strictness of the type
 checking, and remove the mypy pre-commit hook by @kurtmckee
 in #1112
 - Support Python 3.14, and test against PyPy 3.10 and 3.11 by
 @kurtmckee in #1104
 - Development: Migrate to build to test package building in
 CI by @kurtmckee in #1108
 - Development: Improve coverage config and eliminate unused
 test suite code by @kurtmckee in #1115
 - Docs: Standardize CHANGELOG links to PRs by @kurtmckee in
 #1110
 - Docs: Fix Read the Docs builds by @kurtmckee in #1111
 - Docs: Add example of using leeway with nbf by @djw8605 in
 #1034
 - Docs: Refactored docs with autodoc, added PyJWS and
 jwt.algorithms docs by @pachewise in #1045
 - Docs: Documentation improvements for 'sub' and 'jti' claims
 by @cleder in #1088
 - Development: Add pyupgrade as a pre-commit hook by
 @kurtmckee in #1109
 - Add minimum key length validation for HMAC and RSA keys
 (CWE-326). Warns by default via InsecureKeyLengthWarning
 when keys are below minimum recommended lengths per RFC
 7518 Section 3.2 (HMAC) and NIST SP 800-131A (RSA). Pass
 enforce_minimum_key_length=True in options to PyJWT or
 PyJWS to raise InvalidKeyError instead.
 - Refactor PyJWT to own an internal PyJWS instance instead of
 calling global api_jws functions.");

  script_tag(name:"affected", value:"'python-PyJWT' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"python313-PyJWT", rpm:"python313-PyJWT~2.12.1~160000.1.1", rls:"SLES16.0.0"))) {
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
