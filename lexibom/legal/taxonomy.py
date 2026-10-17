"""License normalization engine and taxonomy for code and AI/ML model licenses."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class LicenseCategory(str, Enum):
    """High-level legal classification for software and ML model weight licenses."""

    PERMISSIVE = "PERMISSIVE"
    WEAK_COPYLEFT = "WEAK_COPYLEFT"
    STRONG_COPYLEFT = "STRONG_COPYLEFT"
    NETWORK_COPYLEFT = "NETWORK_COPYLEFT"
    BEHAVIORAL_RAIL = "BEHAVIORAL_RAIL"
    COMMUNITY_RESTRICTED = "COMMUNITY_RESTRICTED"
    NON_COMMERCIAL = "NON_COMMERCIAL"
    PROPRIETARY = "PROPRIETARY"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class LicenseInfo:
    """Rich metadata and canonical classification for a normalized license."""

    canonical_id: str
    name: str
    category: LicenseCategory
    is_spdx: bool
    allows_commercial: bool
    requires_attribution: bool
    has_patent_grant: bool
    has_patent_termination: bool
    has_behavioral_restrictions: bool
    copyleft_scope: str  # "none", "file", "library", "project", "network"
    notice_text: str


MIT_NOTICE_TEXT = """Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

APACHE_2_NOTICE_TEXT = """Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Patent Grant & Defensive Termination (Section 3): Each Contributor hereby grants
to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free,
irrevocable patent license to make, have made, use, offer to sell, sell,
import, and otherwise transfer the Work. If You institute patent litigation
against any entity alleging that the Work or a Contribution incorporated within
the Work constitutes direct or contributory patent infringement, then any patent
licenses granted to You under this License for that Work shall terminate as of
the date such litigation is filed."""

BSD_3_NOTICE_TEXT = """Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED."""

BSD_2_NOTICE_TEXT = """Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED."""

ISC_NOTICE_TEXT = """Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS."""

OPENRAIL_M_NOTICE_TEXT = """CreativeML OpenRAIL-M License (Responsible AI License - Model)
This model and its weights are licensed under the OpenRAIL-M License.
Downstream redistributions and derivative works must retain Attachment A
(Use-Based Restrictions), prohibiting usage for:
- Biometric identification, real-time categorization, or mass surveillance
- Medical diagnosis, clinical decision-making, or treatment advice
- Administration of justice, law enforcement, or democratic processes
- Generating or disseminating verifiable false information to harm others"""

LLAMA_3_NOTICE_TEXT = """Meta Llama 3 Community License Agreement
Built with Meta Llama 3.
1. Redistribution and Attribution: You must provide a copy of this Agreement
   and prominently display "Built with Meta Llama 3" on related websites, UIs,
   and documentation.
2. Commercial Threshold (Section 2): If on the Meta Llama 3 version release
   date, the monthly active users (MAU) of products or services made available
   by or for Licensee is greater than 700 million MAU in the preceding calendar
   month, you must request a separate commercial license from Meta.
3. Acceptable Use: Use is subject to the Meta Llama 3 Acceptable Use Policy."""


LICENSE_CATALOG: dict[str, LicenseInfo] = {
    "MIT": LicenseInfo(
        canonical_id="MIT",
        name="MIT License",
        category=LicenseCategory.PERMISSIVE,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text=MIT_NOTICE_TEXT,
    ),
    "Apache-2.0": LicenseInfo(
        canonical_id="Apache-2.0",
        name="Apache License 2.0",
        category=LicenseCategory.PERMISSIVE,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=True,
        has_patent_termination=True,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text=APACHE_2_NOTICE_TEXT,
    ),
    "BSD-3-Clause": LicenseInfo(
        canonical_id="BSD-3-Clause",
        name="BSD 3-Clause 'New' or 'Revised' License",
        category=LicenseCategory.PERMISSIVE,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text=BSD_3_NOTICE_TEXT,
    ),
    "BSD-2-Clause": LicenseInfo(
        canonical_id="BSD-2-Clause",
        name="BSD 2-Clause 'Simplified' License",
        category=LicenseCategory.PERMISSIVE,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text=BSD_2_NOTICE_TEXT,
    ),
    "ISC": LicenseInfo(
        canonical_id="ISC",
        name="ISC License",
        category=LicenseCategory.PERMISSIVE,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text=ISC_NOTICE_TEXT,
    ),
    "0BSD": LicenseInfo(
        canonical_id="0BSD",
        name="BSD Zero Clause License",
        category=LicenseCategory.PERMISSIVE,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=False,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text="Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.",
    ),
    "Unlicense": LicenseInfo(
        canonical_id="Unlicense",
        name="The Unlicense",
        category=LicenseCategory.PERMISSIVE,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=False,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text="This is free and unencumbered software released into the public domain.",
    ),
    "CC-BY-4.0": LicenseInfo(
        canonical_id="CC-BY-4.0",
        name="Creative Commons Attribution 4.0 International",
        category=LicenseCategory.PERMISSIVE,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text="Licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).",
    ),
    "MPL-2.0": LicenseInfo(
        canonical_id="MPL-2.0",
        name="Mozilla Public License 2.0",
        category=LicenseCategory.WEAK_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=True,
        has_patent_termination=True,
        has_behavioral_restrictions=False,
        copyleft_scope="file",
        notice_text="This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.",
    ),
    "LGPL-2.1-only": LicenseInfo(
        canonical_id="LGPL-2.1-only",
        name="GNU Lesser General Public License v2.1 only",
        category=LicenseCategory.WEAK_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="library",
        notice_text="Licensed under the GNU Lesser General Public License v2.1 (LGPL-2.1-only).",
    ),
    "LGPL-2.1-or-later": LicenseInfo(
        canonical_id="LGPL-2.1-or-later",
        name="GNU Lesser General Public License v2.1 or later",
        category=LicenseCategory.WEAK_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="library",
        notice_text="Licensed under the GNU Lesser General Public License v2.1 or later (LGPL-2.1-or-later).",
    ),
    "LGPL-3.0-only": LicenseInfo(
        canonical_id="LGPL-3.0-only",
        name="GNU Lesser General Public License v3.0 only",
        category=LicenseCategory.WEAK_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=True,
        has_patent_termination=True,
        has_behavioral_restrictions=False,
        copyleft_scope="library",
        notice_text="Licensed under the GNU Lesser General Public License v3.0 (LGPL-3.0-only).",
    ),
    "LGPL-3.0-or-later": LicenseInfo(
        canonical_id="LGPL-3.0-or-later",
        name="GNU Lesser General Public License v3.0 or later",
        category=LicenseCategory.WEAK_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=True,
        has_patent_termination=True,
        has_behavioral_restrictions=False,
        copyleft_scope="library",
        notice_text="Licensed under the GNU Lesser General Public License v3.0 or later (LGPL-3.0-or-later).",
    ),
    "EPL-2.0": LicenseInfo(
        canonical_id="EPL-2.0",
        name="Eclipse Public License 2.0",
        category=LicenseCategory.WEAK_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=True,
        has_patent_termination=True,
        has_behavioral_restrictions=False,
        copyleft_scope="file",
        notice_text="Licensed under the Eclipse Public License v2.0 (EPL-2.0).",
    ),
    "GPL-2.0-only": LicenseInfo(
        canonical_id="GPL-2.0-only",
        name="GNU General Public License v2.0 only",
        category=LicenseCategory.STRONG_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="project",
        notice_text="Licensed under the GNU General Public License v2.0 only (GPL-2.0-only).",
    ),
    "GPL-2.0-or-later": LicenseInfo(
        canonical_id="GPL-2.0-or-later",
        name="GNU General Public License v2.0 or later",
        category=LicenseCategory.STRONG_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="project",
        notice_text="Licensed under the GNU General Public License v2.0 or later (GPL-2.0-or-later).",
    ),
    "GPL-3.0-only": LicenseInfo(
        canonical_id="GPL-3.0-only",
        name="GNU General Public License v3.0 only",
        category=LicenseCategory.STRONG_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=True,
        has_patent_termination=True,
        has_behavioral_restrictions=False,
        copyleft_scope="project",
        notice_text="Licensed under the GNU General Public License v3.0 only (GPL-3.0-only).",
    ),
    "GPL-3.0-or-later": LicenseInfo(
        canonical_id="GPL-3.0-or-later",
        name="GNU General Public License v3.0 or later",
        category=LicenseCategory.STRONG_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=True,
        has_patent_termination=True,
        has_behavioral_restrictions=False,
        copyleft_scope="project",
        notice_text="Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).",
    ),
    "CC-BY-SA-4.0": LicenseInfo(
        canonical_id="CC-BY-SA-4.0",
        name="Creative Commons Attribution-ShareAlike 4.0 International",
        category=LicenseCategory.STRONG_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="project",
        notice_text="Licensed under Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0).",
    ),
    "AGPL-3.0-only": LicenseInfo(
        canonical_id="AGPL-3.0-only",
        name="GNU Affero General Public License v3.0 only",
        category=LicenseCategory.NETWORK_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=True,
        has_patent_termination=True,
        has_behavioral_restrictions=False,
        copyleft_scope="network",
        notice_text="Licensed under the GNU Affero General Public License v3.0 only (AGPL-3.0-only).",
    ),
    "AGPL-3.0-or-later": LicenseInfo(
        canonical_id="AGPL-3.0-or-later",
        name="GNU Affero General Public License v3.0 or later",
        category=LicenseCategory.NETWORK_COPYLEFT,
        is_spdx=True,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=True,
        has_patent_termination=True,
        has_behavioral_restrictions=False,
        copyleft_scope="network",
        notice_text="Licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).",
    ),
    "SSPL-1.0": LicenseInfo(
        canonical_id="SSPL-1.0",
        name="Server Side Public License v1.0",
        category=LicenseCategory.NETWORK_COPYLEFT,
        is_spdx=False,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="network",
        notice_text="Licensed under the Server Side Public License v1.0 (SSPL-1.0).",
    ),
    "OpenRAIL-M": LicenseInfo(
        canonical_id="OpenRAIL-M",
        name="CreativeML OpenRAIL-M (Responsible AI License for Models)",
        category=LicenseCategory.BEHAVIORAL_RAIL,
        is_spdx=False,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=True,
        has_patent_termination=True,
        has_behavioral_restrictions=True,
        copyleft_scope="none",
        notice_text=OPENRAIL_M_NOTICE_TEXT,
    ),
    "OpenRAIL-D": LicenseInfo(
        canonical_id="OpenRAIL-D",
        name="OpenRAIL-D (Responsible AI License for Data)",
        category=LicenseCategory.BEHAVIORAL_RAIL,
        is_spdx=False,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=True,
        has_patent_termination=True,
        has_behavioral_restrictions=True,
        copyleft_scope="none",
        notice_text=OPENRAIL_M_NOTICE_TEXT,
    ),
    "Llama-3-Community": LicenseInfo(
        canonical_id="Llama-3-Community",
        name="Meta Llama 3 Community License Agreement",
        category=LicenseCategory.COMMUNITY_RESTRICTED,
        is_spdx=False,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=True,
        has_behavioral_restrictions=True,
        copyleft_scope="none",
        notice_text=LLAMA_3_NOTICE_TEXT,
    ),
    "Llama-2-Community": LicenseInfo(
        canonical_id="Llama-2-Community",
        name="Meta Llama 2 Community License Agreement",
        category=LicenseCategory.COMMUNITY_RESTRICTED,
        is_spdx=False,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=True,
        has_behavioral_restrictions=True,
        copyleft_scope="none",
        notice_text=LLAMA_3_NOTICE_TEXT.replace("Llama 3", "Llama 2"),
    ),
    "Gemma-Terms-of-Use": LicenseInfo(
        canonical_id="Gemma-Terms-of-Use",
        name="Google Gemma Terms of Use",
        category=LicenseCategory.COMMUNITY_RESTRICTED,
        is_spdx=False,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=True,
        has_behavioral_restrictions=True,
        copyleft_scope="none",
        notice_text="Gemma is provided under and subject to the Gemma Terms of Use (ai.google.dev/gemma/terms), including the Gemma Prohibited Use Policy.",
    ),
    "Custom-Model-Rider": LicenseInfo(
        canonical_id="Custom-Model-Rider",
        name="Custom AI Model Weight Rider License",
        category=LicenseCategory.COMMUNITY_RESTRICTED,
        is_spdx=False,
        allows_commercial=True,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=True,
        copyleft_scope="none",
        notice_text="Subject to Custom Model Weight Rider terms, including usage and scale restrictions.",
    ),
    "CC-BY-NC-4.0": LicenseInfo(
        canonical_id="CC-BY-NC-4.0",
        name="Creative Commons Attribution-NonCommercial 4.0 International",
        category=LicenseCategory.NON_COMMERCIAL,
        is_spdx=True,
        allows_commercial=False,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text="Licensed under Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0). Commercial use is strictly prohibited.",
    ),
    "CC-BY-NC-3.0": LicenseInfo(
        canonical_id="CC-BY-NC-3.0",
        name="Creative Commons Attribution-NonCommercial 3.0 Unported",
        category=LicenseCategory.NON_COMMERCIAL,
        is_spdx=True,
        allows_commercial=False,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text="Licensed under Creative Commons Attribution-NonCommercial 3.0 Unported (CC BY-NC 3.0). Commercial use is strictly prohibited.",
    ),
    "CC-BY-NC-SA-4.0": LicenseInfo(
        canonical_id="CC-BY-NC-SA-4.0",
        name="Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International",
        category=LicenseCategory.NON_COMMERCIAL,
        is_spdx=True,
        allows_commercial=False,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="project",
        notice_text="Licensed under Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0). Commercial use is strictly prohibited.",
    ),
    "CC-BY-NC-ND-4.0": LicenseInfo(
        canonical_id="CC-BY-NC-ND-4.0",
        name="Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International",
        category=LicenseCategory.NON_COMMERCIAL,
        is_spdx=True,
        allows_commercial=False,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text="Licensed under Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0). Commercial use and derivative works are prohibited.",
    ),
    "NonCommercial-Research-Only": LicenseInfo(
        canonical_id="NonCommercial-Research-Only",
        name="Non-Commercial Academic / Research-Only License",
        category=LicenseCategory.NON_COMMERCIAL,
        is_spdx=False,
        allows_commercial=False,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=True,
        copyleft_scope="none",
        notice_text="Restricted to non-commercial academic and scientific research use only.",
    ),
    "Proprietary": LicenseInfo(
        canonical_id="Proprietary",
        name="Proprietary / Commercial License",
        category=LicenseCategory.PROPRIETARY,
        is_spdx=False,
        allows_commercial=False,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=True,
        copyleft_scope="none",
        notice_text="All rights reserved. Proprietary software/model weights.",
    ),
    "UNKNOWN": LicenseInfo(
        canonical_id="UNKNOWN",
        name="Unknown or Unspecified License",
        category=LicenseCategory.UNKNOWN,
        is_spdx=False,
        allows_commercial=False,
        requires_attribution=True,
        has_patent_grant=False,
        has_patent_termination=False,
        has_behavioral_restrictions=False,
        copyleft_scope="none",
        notice_text="No license metadata could be verified for this component.",
    ),
}

_NORMALIZATION_ALIASES: dict[str, str] = {
    # Permissive
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "osi approved :: mit license": "MIT",
    "expat": "MIT",
    "apache-2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "asl 2.0": "Apache-2.0",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "3-clause bsd": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "modified bsd": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "2-clause bsd": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause",
    "isc": "ISC",
    "isc license": "ISC",
    "0bsd": "0BSD",
    "zero-clause bsd": "0BSD",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "cc-by-4.0": "CC-BY-4.0",
    "cc by 4.0": "CC-BY-4.0",
    "creative commons attribution 4.0": "CC-BY-4.0",
    # Weak Copyleft
    "mpl-2.0": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "mpl2": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-2.1-only": "LGPL-2.1-only",
    "lgpl 2.1": "LGPL-2.1-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgpl-2.1+": "LGPL-2.1-or-later",
    "lgpl-2.1-or-later": "LGPL-2.1-or-later",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgpl-3.0-only": "LGPL-3.0-only",
    "lgpl 3.0": "LGPL-3.0-only",
    "lgplv3": "LGPL-3.0-only",
    "lgpl": "LGPL-3.0-only",
    "lgpl-3.0+": "LGPL-3.0-or-later",
    "lgpl-3.0-or-later": "LGPL-3.0-or-later",
    "epl-2.0": "EPL-2.0",
    "eclipse public license 2.0": "EPL-2.0",
    # Strong Copyleft
    "gpl-2.0": "GPL-2.0-only",
    "gpl-2.0-only": "GPL-2.0-only",
    "gpl 2.0": "GPL-2.0-only",
    "gplv2": "GPL-2.0-only",
    "gpl-2": "GPL-2.0-only",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gpl-2.0+": "GPL-2.0-or-later",
    "gpl-2.0-or-later": "GPL-2.0-or-later",
    "gplv2+": "GPL-2.0-or-later",
    "gpl-3.0": "GPL-3.0-only",
    "gpl-3.0-only": "GPL-3.0-only",
    "gpl 3.0": "GPL-3.0-only",
    "gplv3": "GPL-3.0-only",
    "gpl-3": "GPL-3.0-only",
    "gpl": "GPL-3.0-only",
    "gnu general public license v3": "GPL-3.0-only",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gpl-3.0+": "GPL-3.0-or-later",
    "gpl-3.0-or-later": "GPL-3.0-or-later",
    "gplv3+": "GPL-3.0-or-later",
    "cc-by-sa-4.0": "CC-BY-SA-4.0",
    "cc by-sa 4.0": "CC-BY-SA-4.0",
    # Network Copyleft
    "agpl-3.0": "AGPL-3.0-only",
    "agpl-3.0-only": "AGPL-3.0-only",
    "agpl 3.0": "AGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    "agpl-3": "AGPL-3.0-only",
    "agpl": "AGPL-3.0-only",
    "affero gpl": "AGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "agpl-3.0+": "AGPL-3.0-or-later",
    "agpl-3.0-or-later": "AGPL-3.0-or-later",
    "agplv3+": "AGPL-3.0-or-later",
    "sspl-1.0": "SSPL-1.0",
    "sspl": "SSPL-1.0",
    "server side public license": "SSPL-1.0",
    # Behavioral / RAIL
    "openrail-m": "OpenRAIL-M",
    "openrail": "OpenRAIL-M",
    "openrail++": "OpenRAIL-M",
    "creativeml openrail-m": "OpenRAIL-M",
    "creativeml-openrail-m": "OpenRAIL-M",
    "bigscience-openrail-m": "OpenRAIL-M",
    "bigscience openrail-m": "OpenRAIL-M",
    "openrail-m-v1": "OpenRAIL-M",
    "openrail-d": "OpenRAIL-D",
    "creativeml openrail-d": "OpenRAIL-D",
    # Community / Model Riders
    "llama-3-community": "Llama-3-Community",
    "llama 3 community": "Llama-3-Community",
    "llama 3 community license": "Llama-3-Community",
    "meta llama 3 community license": "Llama-3-Community",
    "llama3": "Llama-3-Community",
    "llama-3": "Llama-3-Community",
    "llama-2-community": "Llama-2-Community",
    "llama 2 community": "Llama-2-Community",
    "llama 2 community license": "Llama-2-Community",
    "llama-community": "Llama-3-Community",
    "llama community license": "Llama-3-Community",
    "llama2": "Llama-2-Community",
    "llama-2": "Llama-2-Community",
    "gemma-terms-of-use": "Gemma-Terms-of-Use",
    "gemma terms of use": "Gemma-Terms-of-Use",
    "gemma": "Gemma-Terms-of-Use",
    "custom-model-rider": "Custom-Model-Rider",
    "custom model rider": "Custom-Model-Rider",
    # Non-Commercial
    "cc-by-nc-4.0": "CC-BY-NC-4.0",
    "cc by-nc 4.0": "CC-BY-NC-4.0",
    "cc-by-nc": "CC-BY-NC-4.0",
    "cc by-nc": "CC-BY-NC-4.0",
    "creative commons attribution-noncommercial 4.0": "CC-BY-NC-4.0",
    "creative commons attribution noncommercial 4.0": "CC-BY-NC-4.0",
    "cc-by-nc-3.0": "CC-BY-NC-3.0",
    "cc by-nc 3.0": "CC-BY-NC-3.0",
    "cc-by-nc-sa-4.0": "CC-BY-NC-SA-4.0",
    "cc by-nc-sa 4.0": "CC-BY-NC-SA-4.0",
    "cc-by-nc-nd-4.0": "CC-BY-NC-ND-4.0",
    "cc by-nc-nd 4.0": "CC-BY-NC-ND-4.0",
    "noncommercial": "NonCommercial-Research-Only",
    "non-commercial": "NonCommercial-Research-Only",
    "noncommercial-research-only": "NonCommercial-Research-Only",
    "research-only": "NonCommercial-Research-Only",
    "research only": "NonCommercial-Research-Only",
    "academic-only": "NonCommercial-Research-Only",
    "cc-by-nc-research": "CC-BY-NC-4.0",
    # Proprietary
    "proprietary": "Proprietary",
    "commercial": "Proprietary",
    "all rights reserved": "Proprietary",
}


_RESTRICTIVENESS_RANK: dict[str, int] = {
    "Unlicense": 0,
    "0BSD": 1,
    "MIT": 2,
    "ISC": 3,
    "BSD-2-Clause": 4,
    "BSD-3-Clause": 5,
    "Apache-2.0": 6,
    "CC-BY-4.0": 7,
    "MPL-2.0": 20,
    "EPL-2.0": 21,
    "LGPL-2.1-or-later": 22,
    "LGPL-2.1-only": 23,
    "LGPL-3.0-or-later": 24,
    "LGPL-3.0-only": 25,
    "OpenRAIL-M": 40,
    "OpenRAIL-D": 41,
    "Llama-3-Community": 42,
    "Llama-2-Community": 43,
    "Gemma-Terms-of-Use": 44,
    "Custom-Model-Rider": 45,
    "CC-BY-SA-4.0": 60,
    "GPL-3.0-or-later": 61,
    "GPL-3.0-only": 62,
    "GPL-2.0-or-later": 63,
    "GPL-2.0-only": 64,
    "AGPL-3.0-or-later": 80,
    "AGPL-3.0-only": 81,
    "SSPL-1.0": 82,
    "CC-BY-NC-4.0": 90,
    "CC-BY-NC-3.0": 91,
    "CC-BY-NC-SA-4.0": 92,
    "CC-BY-NC-ND-4.0": 93,
    "NonCommercial-Research-Only": 94,
    "Proprietary": 95,
    "UNKNOWN": 100,
}


def _normalize_single_token(token: str) -> str:
    cleaned = token.strip().strip("()")
    if not cleaned or cleaned.lower() in ("unknown", "none", "null", "n/a", "unspecified"):
        return "UNKNOWN"

    # Strip SPDX WITH exception suffix if present (e.g. "Apache-2.0 WITH LLVM-exception")
    cleaned = re.split(r"\s+WITH\s+", cleaned, flags=re.IGNORECASE)[0].strip()

    if cleaned in LICENSE_CATALOG:
        return cleaned

    lowered = re.sub(r"\s+", " ", cleaned.lower()).strip()
    if lowered in _NORMALIZATION_ALIASES:
        return _NORMALIZATION_ALIASES[lowered]

    # Heuristic pattern matching for single license strings
    if "openrail-d" in lowered:
        return "OpenRAIL-D"
    if "openrail" in lowered or "rail-m" in lowered:
        return "OpenRAIL-M"
    if "llama-3" in lowered or "llama 3" in lowered or "llama3" in lowered:
        return "Llama-3-Community"
    if "llama-2" in lowered or "llama 2" in lowered or "llama2" in lowered:
        return "Llama-2-Community"
    if "llama" in lowered and "community" in lowered:
        return "Llama-3-Community"
    if "gemma" in lowered:
        return "Gemma-Terms-of-Use"
    if "cc-by-nc-sa" in lowered or "cc by-nc-sa" in lowered:
        return "CC-BY-NC-SA-4.0"
    if "cc-by-nc-nd" in lowered or "cc by-nc-nd" in lowered:
        return "CC-BY-NC-ND-4.0"
    if "cc-by-nc-3" in lowered or "cc by-nc 3" in lowered:
        return "CC-BY-NC-3.0"
    if "cc-by-nc" in lowered or "cc by-nc" in lowered or "noncommercial 4.0" in lowered:
        return "CC-BY-NC-4.0"
    if (
        "non-commercial" in lowered
        or "noncommercial" in lowered
        or "research-only" in lowered
        or "research only" in lowered
    ):
        return "NonCommercial-Research-Only"
    if "agpl" in lowered or "affero" in lowered:
        if "or later" in lowered or "+" in lowered or "or-later" in lowered:
            return "AGPL-3.0-or-later"
        return "AGPL-3.0-only"
    if "sspl" in lowered or "server side public" in lowered:
        return "SSPL-1.0"
    if "lgpl" in lowered or "lesser general public" in lowered:
        if "2.1" in lowered:
            return (
                "LGPL-2.1-or-later"
                if ("+" in lowered or "or-later" in lowered or "or later" in lowered)
                else "LGPL-2.1-only"
            )
        return (
            "LGPL-3.0-or-later"
            if ("+" in lowered or "or-later" in lowered or "or later" in lowered)
            else "LGPL-3.0-only"
        )
    if "gpl" in lowered or "general public license" in lowered:
        if "2.0" in lowered or "v2" in lowered or "version 2" in lowered:
            return (
                "GPL-2.0-or-later"
                if ("+" in lowered or "or-later" in lowered or "or later" in lowered)
                else "GPL-2.0-only"
            )
        return (
            "GPL-3.0-or-later"
            if ("+" in lowered or "or-later" in lowered or "or later" in lowered)
            else "GPL-3.0-only"
        )
    if re.search(r"\bmpl\b", lowered) or "mozilla public" in lowered:
        return "MPL-2.0"
    if "apache" in lowered:
        return "Apache-2.0"
    if "bsd" in lowered:
        if "2-clause" in lowered or "simplified" in lowered:
            return "BSD-2-Clause"
        if "0bsd" in lowered or "zero" in lowered:
            return "0BSD"
        return "BSD-3-Clause"
    if re.search(r"\bmit\b", lowered):
        return "MIT"
    if re.search(r"\bisc\b", lowered):
        return "ISC"
    if "rider" in lowered:
        return "Custom-Model-Rider"

    return "UNKNOWN"


def _strip_outer_parens(expr: str) -> str:
    s = expr.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        matched_outer = True
        for idx, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and idx < len(s) - 1:
                    matched_outer = False
                    break
        if matched_outer and depth == 0:
            s = s[1:-1].strip()
        else:
            break
    return s


def _split_top_level_spdx(expr: str, operator: str) -> list[str]:
    """Split an SPDX expression by top-level operator ('OR' or 'AND') outside parentheses."""
    parts: list[str] = []
    depth = 0
    last_idx = 0
    op_upper = operator.upper()
    i = 0
    n = len(expr)

    while i < n:
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            if op_upper == "OR" and ch == "/" and i > 0 and i < n - 1:
                if expr[i - 1].isspace() or expr[i + 1].isspace() or expr[i + 1].isalnum():
                    # Avoid splitting URLs or repo paths unless surrounded by spaces or standard license tokens
                    if expr[i - 1].isspace() and expr[i + 1].isspace():
                        parts.append(expr[last_idx:i].strip())
                        last_idx = i + 1
            elif expr[i].isspace():
                match = re.match(rf"^\s+{op_upper}\s+", expr[i:], flags=re.IGNORECASE)
                if match:
                    parts.append(expr[last_idx:i].strip())
                    i += match.end()
                    last_idx = i
                    continue
        i += 1

    if parts:
        parts.append(expr[last_idx:].strip())
    return parts


def normalize_license(raw_license: str | None) -> str:
    """Normalize a raw license string or compound SPDX expression into a canonical ID."""
    if not raw_license:
        return "UNKNOWN"

    cleaned = _strip_outer_parens(raw_license)
    if not cleaned:
        return "UNKNOWN"

    # SPDX precedence: 'OR' has lower precedence than 'AND', so split top-level 'OR' first.
    or_parts = _split_top_level_spdx(cleaned, "OR")
    if len(or_parts) > 1:
        normalized_options = [normalize_license(part) for part in or_parts]
        valid_options = [opt for opt in normalized_options if opt != "UNKNOWN"]
        if valid_options:
            return min(
                valid_options,
                key=lambda lic: _RESTRICTIVENESS_RANK.get(lic, 99),
            )

    # Next, split top-level 'AND' (higher precedence than 'OR').
    and_parts = _split_top_level_spdx(cleaned, "AND")
    if len(and_parts) > 1:
        normalized_reqs = [normalize_license(part) for part in and_parts]
        valid_reqs = [req for req in normalized_reqs if req != "UNKNOWN"]
        if valid_reqs:
            return max(
                valid_reqs,
                key=lambda lic: _RESTRICTIVENESS_RANK.get(lic, 99),
            )

    return _normalize_single_token(cleaned)


def classify_license(license_id_or_raw: str | None) -> LicenseInfo:
    """Return the canonical LicenseInfo for a normalized or raw license string."""
    canonical = normalize_license(license_id_or_raw)
    return LICENSE_CATALOG.get(canonical, LICENSE_CATALOG["UNKNOWN"])


class LicenseTaxonomy:
    """Facade for license normalization, lookup, and taxonomy classification."""

    @staticmethod
    def normalize(raw_license: str | None) -> str:
        """Normalize a raw license string into its canonical identifier."""
        return normalize_license(raw_license)

    @staticmethod
    def get_info(license_id_or_raw: str | None) -> LicenseInfo:
        """Get full LicenseInfo metadata for any license identifier or raw string."""
        return classify_license(license_id_or_raw)

    @staticmethod
    def get_category(license_id_or_raw: str | None) -> LicenseCategory:
        """Return the LicenseCategory for any license identifier or raw string."""
        return classify_license(license_id_or_raw).category
