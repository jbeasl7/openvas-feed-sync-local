# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.1021.1");
  script_cve_id("CVE-2012-2143", "CVE-2012-2655", "CVE-2012-3488", "CVE-2012-3489");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 03:22:42 +0000 (Thu, 15 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:1021-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:1021-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20121021-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'PostgreSQL' package(s) announced via the SUSE-SU-2012:1021-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides PostgreSQL 8.3.20. As part of this update, the packaging scheme has been changed to accomodate an optional parallel installation of newer PostgreSQL versions.

The changes in 8.3.20 are:

 *

 Prevent access to external files/URLs via XML entity references. xml_parse() would attempt to fetch external files or URLs as needed to resolve DTD and entity references in an XML value, thus allowing unprivileged database users to attempt to fetch data with the privileges of the database server (CVE-2012-3489, bnc#776524).

 *

 Prevent access to external files/URLs via
'contrib/xml2''s xslt_process(). libxslt offers the ability to read and write both files and URLs through stylesheet commands, thus allowing unprivileged database users to both read and write data with the privileges of the database server. Disable that through proper use of libxslt's security options. (CVE-2012-3488, bnc#776523). Also, remove xslt_process()'s ability to fetch documents and stylesheets from external files/URLs.

 *

 Fix incorrect password transformation in contrib/pgcrypto's DES crypt() function. If a password string contained the byte value 0x80, the remainder of the password was ignored, causing the password to be much weaker than it appeared. With this fix, the rest of the string is properly included in the DES hash. Any stored password values that are affected by this bug will thus no longer match, so the stored values may need to be updated.
(CVE-2012-2143)

 *

 Ignore SECURITY DEFINER and SET attributes for a procedural language's call handler. Applying such attributes to a call handler could crash the server.
(CVE-2012-2655)

 *

 Allow numeric timezone offsets in timestamp input to be up to 16 hours away from UTC. Some historical time zones have offsets larger than 15 hours, the previous limit. This could result in dumped data values being rejected during reload.

 *

 Fix timestamp conversion to cope when the given time is exactly the last DST transition time for the current timezone. This oversight has been there a long time, but was not noticed previously because most DST-using zones are presumed to have an indefinite sequence of future DST transitions.

 *

 Fix text to name and char to name casts to perform string truncation correctly in multibyte encodings.

 *

 Fix memory copying bug in to_tsquery().

 *

 Fix slow session startup when pg_attribute is very large. If pg_attribute exceeds one-fourth of shared_buffers, cache rebuilding code that is sometimes needed during session start would trigger the synchronized-scan logic, causing it to take many times longer than normal. The problem was particularly acute if many new sessions were starting at once.

 *

 Ensure sequential scans check for query cancel reasonably often. A scan encountering many consecutive pages that contain no live tuples would not respond to interrupts meanwhile.

 *

 Show whole-row ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'PostgreSQL' package(s) on SUSE Linux Enterprise Desktop 11-SP1, SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.3.20~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.3.20~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.3.20~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-init", rpm:"postgresql-init~9.1~0.6.10.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.3.20~0.4.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.3.20~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.3.20~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.3.20~0.4.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-init", rpm:"postgresql-init~9.1~0.6.10.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.3.20~0.4.1", rls:"SLES11.0SP2"))) {
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
