# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2388.1");
  script_cve_id("CVE-2015-8325", "CVE-2016-1908", "CVE-2016-3115", "CVE-2016-6210", "CVE-2016-6515");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-17 19:09:13 +0000 (Mon, 17 Apr 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2388-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2388-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162388-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992533");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-September/002289.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2016:2388-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for OpenSSH fixes the following issues:

- Prevent user enumeration through the timing of password processing.
 (bsc#989363, CVE-2016-6210)
- Allow lowering the DH groups parameter limit in server as well as when GSSAPI
 key exchange is used. (bsc#948902)
- Sanitize input for xauth(1). (bsc#970632, CVE-2016-3115)
- Prevent X11 SECURITY circumvention when forwarding X11 connections.
 (bsc#962313, CVE-2016-1908)
- Disable DH parameters under 2048 bits by default and allow lowering the limit back
 to the RFC 4419 specified minimum through an option. (bsc#932483, bsc#948902)
- Ignore PAM environment when using login. (bsc#975865, CVE-2015-8325)
- Limit the accepted password length (prevents a possible denial of service).
 (bsc#992533, CVE-2016-6515)
- Relax version requires for the openssh-askpass sub-package. (bsc#962794)
- Avoid complaining about unset DISPLAY variable. (bsc#981654)
- Initialize message id to prevent connection breakups in some cases. (bsc#959096)");

  script_tag(name:"affected", value:"'openssh' package(s) on SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.2p2~0.33.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~6.2p2~0.33.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~6.2p2~0.33.5", rls:"SLES11.0SP3"))) {
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
