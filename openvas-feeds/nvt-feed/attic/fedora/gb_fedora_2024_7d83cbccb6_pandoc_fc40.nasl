# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886352");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2023-35936", "CVE-2023-38745");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-03 13:43:26 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-29 02:11:38 +0000 (Fri, 29 Mar 2024)");
  script_name("Fedora: Security Advisory for pandoc (FEDORA-2024-7d83cbccb6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-7d83cbccb6");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/C6UYABHN6WH7AAK6D3Y6IAPFNIS2JC3R");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pandoc'
  package(s) announced via the FEDORA-2024-7d83cbccb6 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pandoc is a Haskell library for converting from one markup format to another.
The formats it can handle include

  - light markup formats (many variants of Markdown, reStructuredText, AsciiDoc,
Org-mode, Muse, Textile, txt2tags) - HTML formats (HTML 4 and 5) - Ebook
formats (EPUB v2 and v3, FB2) - Documentation formats (GNU TexInfo, Haddock) -
Roff formats (man, ms) - TeX formats (LaTeX, ConTeXt) - Typst - XML formats
(DocBook 4 and 5, JATS, TEI Simple, OpenDocument) - Outline formats (OPML) -
Bibliography formats (BibTeX, BibLaTeX, CSL JSON, CSL YAML, RIS) - Word
processor formats (Docx, RTF, ODT) - Interactive notebook formats (Jupyter
notebook ipynb) - Page layout formats (InDesign ICML) - Wiki markup formats
(MediaWiki, DokuWiki, TikiWiki, TWiki, Vimwiki, XWiki, ZimWiki, Jira wiki,
Creole) - Slide show formats (LaTeX Beamer, PowerPoint, Slidy, reveal.js,
Slideous, S5, DZSlides) - Data formats (CSV and TSV tables) - PDF (via external
programs such as pdflatex or wkhtmltopdf)

Pandoc can convert mathematical content in documents between TeX, MathML, Word
equations, roff eqn, typst, and plain text. It includes a powerful system for
automatic citations and bibliographies, and it can be customized extensively
using templates, filters, and custom readers and writers written in Lua.

For the pandoc command-line program, see the &#39, pandoc-cli&#39, package.

For pdf output please also install pandoc-pdf or weasyprint.");

  script_tag(name:"affected", value:"'pandoc' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
