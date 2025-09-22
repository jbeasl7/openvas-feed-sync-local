# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0045.1");
  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0045-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0045-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150045-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the SUSE-SU-2015:0045-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The XOrg X11 server was updated to fix 12 security issues:

 * Denial of service due to unchecked malloc in client authentication
 (CVE-2014-8091).
 * Integer overflows calculating memory needs for requests
 (CVE-2014-8092).
 * Integer overflows calculating memory needs for requests in GLX
 extension (CVE-2014-8093).
 * Integer overflows calculating memory needs for requests in DRI2
 extension (CVE-2014-8094).
 * Out of bounds access due to not validating length or offset values
 in requests in XInput extension (CVE-2014-8095).
 * Out of bounds access due to not validating length or offset values
 in requests in XC-MISC extension (CVE-2014-8096).
 * Out of bounds access due to not validating length or offset values
 in requests in DBE extension (CVE-2014-8097).
 * Out of bounds access due to not validating length or offset values
 in requests in GLX extension (CVE-2014-8098).
 * Out of bounds access due to not validating length or offset values
 in requests in XVideo extension (CVE-2014-8099).
 * Out of bounds access due to not validating length or offset values
 in requests in Render extension (CVE-2014-8100).
 * Out of bounds access due to not validating length or offset values
 in requests in RandR extension (CVE-2014-8101).
 * Out of bounds access due to not validating length or offset values
 in requests in XFixes extension (CVE-2014-8102).

Additionally, these non-security issues were fixed:

 * Fix crash in RENDER protocol, PanoramiX wrappers (bnc#864911).
 * Some formats used for pictures did not work with the chosen
 framebuffer format (bnc#886213).

Security Issues:

 * CVE-2014-8091
 * CVE-2014-8092
 * CVE-2014-8093
 * CVE-2014-8094
 * CVE-2014-8095
 * CVE-2014-8096
 * CVE-2014-8097
 * CVE-2014-8098
 * CVE-2014-8099
 * CVE-2014-8100
 * CVE-2014-8101
 * CVE-2014-8102");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~7.4~27.101.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.4~27.101.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~7.4~27.101.1", rls:"SLES11.0SP3"))) {
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
