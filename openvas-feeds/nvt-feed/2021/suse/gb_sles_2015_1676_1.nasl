# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1676.1");
  script_cve_id("CVE-2015-3813", "CVE-2015-4652", "CVE-2015-6241", "CVE-2015-6242", "CVE-2015-6243", "CVE-2015-6244", "CVE-2015-6245", "CVE-2015-6246", "CVE-2015-6247", "CVE-2015-6248", "CVE-2015-6249");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:10 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1676-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1676-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151676-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941500");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-October/001609.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.7.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2015:1676-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wireshark has been updated to 1.12.7. (FATE#319388)

The following vulnerabilities have been fixed:
* Wireshark could crash when adding an item to the protocol tree. wnpa-sec-2015-21 CVE-2015-6241
* Wireshark could attempt to free invalid memory. wnpa-sec-2015-22 CVE-2015-6242
* Wireshark could crash when searching for a protocol dissector. wnpa-sec-2015-23 CVE-2015-6243
* The ZigBee dissector could crash. wnpa-sec-2015-24 CVE-2015-6244
* The GSM RLC/MAC dissector could go into an infinite loop. wnpa-sec-2015-25 CVE-2015-6245
* The WaveAgent dissector could crash. wnpa-sec-2015-26 CVE-2015-6246
* The OpenFlow dissector could go into an infinite loop. wnpa-sec-2015-27 CVE-2015-6247
* Wireshark could crash due to invalid ptvcursor length checking. wnpa-sec-2015-28 CVE-2015-6248
* The WCCP dissector could crash. wnpa-sec-2015-29 CVE-2015-6249
* Further bug fixes and updated protocol support as listed in:
 [link moved to references]

Also a fix from 1.12.6 in GSM DTAP was backported. (bnc#935158 CVE-2015-4652)");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.12.7~0.5.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.12.7~0.5.3", rls:"SLES11.0SP4"))) {
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
